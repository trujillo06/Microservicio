from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import List, Optional
from pydantic import BaseModel, EmailStr, Field, field_validator
import mysql.connector
from mysql.connector import pooling
import uvicorn
import os
import re
from dotenv import load_dotenv
from contextlib import contextmanager

# Cargar variables de entorno
load_dotenv()

# Configuración de la aplicación
app = FastAPI(
    title="API de Empleados",
    description="Microservicio para gestionar empleados",
    version="1.0.0"
)

# Configuración de CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=[os.getenv("ALLOWED_ORIGINS", "*").split(",")],  # En producción, especificar dominios concretos
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configuración de seguridad
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

# Configuración de conexión a base de datos utilizando pool de conexiones
db_config = {
    "host": os.getenv("DB_HOST"),
    "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASSWORD"),
    "database": os.getenv("DB_NAME"),
    "port": int(os.getenv("DB_PORT", "3306")),
}

# Crear un pool de conexiones para mejorar rendimiento y seguridad
# Nota: El pool solo se inicializa, pero no se crean conexiones hasta que se soliciten
connection_pool = pooling.MySQLConnectionPool(
    pool_name="empleados_pool",
    pool_size=5,
    pool_reset_session=True,  # Asegura que las sesiones se resetean al devolver conexiones
    **db_config
)


# Context manager para manejar conexiones automáticamente
@contextmanager
def get_db_connection():
    conn = None
    try:
        # La conexión solo se obtiene cuando se entra en este contexto (cuando se llama a la ruta)
        conn = connection_pool.get_connection()
        yield conn
    except mysql.connector.Error as e:
        print(f"Error de conexión a la base de datos: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error de conexión a la base de datos"
        )
    finally:
        # La conexión se cierra automáticamente al salir del contexto
        if conn:
            conn.close()


# Modelos de datos mejorados con validaciones
class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Optional[str] = None


# Modelo de usuario actualizado para coincidir con la estructura de la tabla
class UserLogin(BaseModel):
    correo: EmailStr  # Cambiado de username a correo
    password: str  # Esto coincide con el campo contraseña


class EmpleadoBase(BaseModel):
    nombre: str = Field(..., min_length=2, max_length=100)
    apellido_paterno: str = Field(..., min_length=2, max_length=100)
    apellido_materno: Optional[str] = Field(None, min_length=2, max_length=100)
    fecha_nacimiento: str
    sexo: int = Field(..., ge=1)
    estado_civil: int = Field(..., ge=1)
    direccion: Optional[str] = Field(None, max_length=255)
    telefono: Optional[str] = Field(None, max_length=20)
    curp: str = Field(..., min_length=18, max_length=18)
    correo: EmailStr
    rfc: str = Field(..., min_length=12, max_length=13)
    nss: str = Field(..., min_length=11, max_length=11)
    foto: Optional[str] = None
    fecha_ingreso: str
    tipo_contrato: int = Field(..., ge=1)
    puesto: int = Field(..., ge=1)
    departamento: int = Field(..., ge=1)
    sucursal: int = Field(..., ge=1)
    turno: int = Field(..., ge=1)
    salario: float = Field(..., gt=0)
    usuario: Optional[int] = None

    # Validadores actualizados a Pydantic V2
    @field_validator('curp')
    @classmethod
    def validate_curp(cls, v):
        pattern = r'^[A-Z]{4}[0-9]{6}[HM][A-Z]{5}[0-9A-Z]{2}$'
        if not re.match(pattern, v):
            raise ValueError('CURP inválido')
        return v

    @field_validator('rfc')
    @classmethod
    def validate_rfc(cls, v):
        pattern = r'^[A-Z]{3,4}[0-9]{6}[A-Z0-9]{3}$'
        if not re.match(pattern, v):
            raise ValueError('RFC inválido')
        return v

    @field_validator('nss')
    @classmethod
    def validate_nss(cls, v):
        if not v.isdigit() or len(v) != 11:
            raise ValueError('NSS debe contener 11 dígitos numéricos')
        return v

    @field_validator('fecha_nacimiento', 'fecha_ingreso')
    @classmethod
    def validate_fecha(cls, v):
        try:
            datetime.strptime(v, '%Y-%m-%d')
        except ValueError:
            raise ValueError('Formato de fecha inválido. Use YYYY-MM-DD')
        return v

    @field_validator('telefono')
    @classmethod
    def validate_telefono(cls, v):
        if v and not re.match(r'^\+?[0-9]{10,15}$', v):
            raise ValueError('Formato de teléfono inválido')
        return v


class EmpleadoCreate(EmpleadoBase):
    doc_acta_n: Optional[str] = None
    doc_curp: Optional[str] = None
    doc_ine: Optional[str] = None
    doc_comprobante_domicilio: Optional[str] = None
    doc_comprobante_estudios: Optional[str] = None
    doc_nss: Optional[str] = None
    doc_constancia_fiscal: Optional[str] = None
    doc_contrato: Optional[str] = None


class EmpleadoResponse(EmpleadoBase):
    id_empleado: int

    class Config:
        from_attributes = True  # Reemplaza orm_mode=True


class BusquedaEmpleado(BaseModel):
    termino: str = Field(..., min_length=1, max_length=100)
    campo: Optional[str] = Field(None, pattern=r'^[a-zA-Z_]+$')  # Cambiado regex por pattern


# Configuración de autenticación
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


# Middleware para sanitizar consultas SQL
def sanitize_sql_input(value):
    if isinstance(value, str):
        # Eliminar caracteres que podrían ser usados en ataques
        sanitized = re.sub(r'[;\'"\\]', '', value)
        return sanitized
    return value


# Funciones de seguridad mejoradas
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta if expires_delta else timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Credenciales no válidas",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception

    # Verificar en la base de datos si el usuario existe
    # Actualizado para coincidir con la estructura de la tabla de usuarios
    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True, prepared=True)
        try:
            query = "SELECT id_usuario, nombre, correo, rol FROM Usuarios WHERE correo = %s"
            cursor.execute(query, (token_data.username,))
            user = cursor.fetchone()
            if user is None:
                raise credentials_exception
            return user
        finally:
            cursor.close()


# Endpoints de autenticación - Actualizado para usar los nombres de campo correctos
@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    # Usando context manager para manejar la conexión automáticamente
    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True, prepared=True)
        try:
            # Consulta actualizada para coincidir con la estructura de la tabla
            query = """
                SELECT id_usuario, nombre, correo, contraseña, rol, fecha_registro 
                FROM Usuarios WHERE correo = %s
            """
            cursor.execute(query, (form_data.username,))  # form_data.username corresponde a correo
            user = cursor.fetchone()

            if not user or user["contraseña"] != form_data.password:
                # Retardo adicional para prevenir ataques de timing
                import time
                time.sleep(0.5)
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Usuario o contraseña incorrectos",
                    headers={"WWW-Authenticate": "Bearer"},
                )

            access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
            access_token = create_access_token(
                data={"sub": user["correo"], "nombre": user["nombre"], "role": user["rol"]},
                expires_delta=access_token_expires
            )
            return {"access_token": access_token, "token_type": "bearer"}
        finally:
            cursor.close()


# Endpoints de empleados
@app.get("/empleados/", response_model=List[EmpleadoResponse])
async def get_empleados(current_user: dict = Depends(get_current_user), skip: int = 0, limit: int = 100):
    # Validación adicional de parámetros
    if skip < 0 or limit < 1 or limit > 1000:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Parámetros de paginación inválidos"
        )

    # Usando context manager para manejar la conexión automáticamente
    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True, prepared=True)
        try:
            query = """
                SELECT * FROM Empleados
                ORDER BY id_empleado
                LIMIT %s OFFSET %s
                """
            cursor.execute(query, (limit, skip))
            empleados = cursor.fetchall()
            return empleados
        finally:
            cursor.close()


@app.get("/empleados/{empleado_id}", response_model=EmpleadoResponse)
async def get_empleado(empleado_id: int, current_user: dict = Depends(get_current_user)):
    if empleado_id <= 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="ID de empleado inválido"
        )

    # Usando context manager para manejar la conexión automáticamente
    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True, prepared=True)
        try:
            query = "SELECT * FROM Empleados WHERE id_empleado = %s"
            cursor.execute(query, (empleado_id,))
            empleado = cursor.fetchone()
            if empleado is None:
                raise HTTPException(status_code=404, detail="Empleado no encontrado")
            return empleado
        finally:
            cursor.close()


@app.post("/empleados/", response_model=EmpleadoResponse, status_code=status.HTTP_201_CREATED)
async def create_empleado(empleado: EmpleadoCreate, current_user: dict = Depends(get_current_user)):
    # Usando context manager para manejar la conexión automáticamente
    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True, prepared=True)
        try:
            # Verificar si ya existe un empleado con CURP, correo, RFC o NSS existente
            query = """
                SELECT id_empleado FROM Empleados 
                WHERE curp = %s OR correo = %s OR rfc = %s OR nss = %s
                """
            cursor.execute(query, (empleado.curp, empleado.correo, empleado.rfc, empleado.nss))

            if cursor.fetchone():
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Ya existe un empleado con CURP, correo, RFC o NSS proporcionado"
                )

            # Preparar los campos para la inserción
            campos = empleado.model_dump(exclude_unset=True)  # Cambiado dict() por model_dump()
            campos_nombres = list(campos.keys())
            placeholders = ", ".join(["%s"] * len(campos_nombres))
            campos_str = ", ".join(campos_nombres)

            query = f"INSERT INTO Empleados ({campos_str}) VALUES ({placeholders})"
            cursor.execute(query, [campos[nombre] for nombre in campos_nombres])
            conn.commit()

            # Obtener el ID del empleado recién insertado
            new_id = cursor.lastrowid

            # Recuperar el empleado completo
            cursor.execute("SELECT * FROM Empleados WHERE id_empleado = %s", (new_id,))
            new_empleado = cursor.fetchone()

            return new_empleado
        except mysql.connector.Error as e:
            conn.rollback()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Error al crear empleado: {str(e)}"
            )
        finally:
            cursor.close()


@app.put("/empleados/{empleado_id}", response_model=EmpleadoResponse)
async def update_empleado(empleado_id: int, empleado_update: EmpleadoCreate,
                          current_user: dict = Depends(get_current_user)):
    if empleado_id <= 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="ID de empleado inválido"
        )

    # Usando context manager para manejar la conexión automáticamente
    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True, prepared=True)
        try:
            # Verificar si el empleado existe
            cursor.execute("SELECT id_empleado FROM Empleados WHERE id_empleado = %s", (empleado_id,))
            if not cursor.fetchone():
                raise HTTPException(status_code=404, detail="Empleado no encontrado")

            # Verificar que no haya conflictos con otros empleados
            query = """
                SELECT id_empleado FROM Empleados 
                WHERE (curp = %s OR correo = %s OR rfc = %s OR nss = %s) AND id_empleado != %s
                """
            cursor.execute(query, (empleado_update.curp, empleado_update.correo, empleado_update.rfc, empleado_update.nss, empleado_id))
            if cursor.fetchone():
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Ya existe otro empleado con CURP, correo, RFC o NSS proporcionado"
                )

            # Preparar los campos para la actualización
            campos = empleado_update.model_dump(exclude_unset=True)  # Cambiado dict() por model_dump()
            set_clause = ", ".join([f"{k} = %s" for k in campos.keys()])
            values = list(campos.values())
            values.append(empleado_id)  # Para la condición WHERE

            query = f"UPDATE Empleados SET {set_clause} WHERE id_empleado = %s"
            cursor.execute(query, values)
            conn.commit()

            # Recuperar el empleado actualizado
            cursor.execute("SELECT * FROM Empleados WHERE id_empleado = %s", (empleado_id,))
            updated_empleado = cursor.fetchone()

            return updated_empleado
        except mysql.connector.Error as e:
            conn.rollback()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Error al actualizar empleado: {str(e)}"
            )
        finally:
            cursor.close()


@app.delete("/empleados/{empleado_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_empleado(empleado_id: int, current_user: dict = Depends(get_current_user)):
    if empleado_id <= 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="ID de empleado inválido"
        )

    # Usando context manager para manejar la conexión automáticamente
    with get_db_connection() as conn:
        cursor = conn.cursor(prepared=True)
        try:
            # Verificar si el empleado existe
            cursor.execute("SELECT id_empleado FROM Empleados WHERE id_empleado = %s", (empleado_id,))
            if not cursor.fetchone():
                raise HTTPException(status_code=404, detail="Empleado no encontrado")

            # Eliminar el empleado
            cursor.execute("DELETE FROM Empleados WHERE id_empleado = %s", (empleado_id,))
            conn.commit()

            return None
        except mysql.connector.Error as e:
            conn.rollback()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Error al eliminar empleado: {str(e)}"
            )
        finally:
            cursor.close()


@app.post("/empleados/buscar/", response_model=List[EmpleadoResponse])
async def buscar_empleados(busqueda: BusquedaEmpleado, current_user: dict = Depends(get_current_user)):
    # Usando context manager para manejar la conexión automáticamente
    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True, prepared=True)
        try:
            # Lista de campos permitidos para la búsqueda
            campos_permitidos = [
                "nombre", "apellido_paterno", "apellido_materno",
                "curp", "correo", "rfc", "nss", "telefono"
            ]

            # Construir la consulta según el campo especificado
            if busqueda.campo:
                # Validar que el campo especificado esté permitido
                if busqueda.campo not in campos_permitidos:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"Campo de búsqueda no permitido. Opciones válidas: {', '.join(campos_permitidos)}"
                    )

                # Buscar en un campo específico
                query = f"SELECT * FROM Empleados WHERE {busqueda.campo} LIKE %s"
                cursor.execute(query, (f"%{busqueda.termino}%",))
            else:
                # Buscar en varios campos comunes
                query = """
                SELECT * FROM Empleados 
                WHERE nombre LIKE %s 
                   OR apellido_paterno LIKE %s 
                   OR apellido_materno LIKE %s 
                   OR curp LIKE %s 
                   OR rfc LIKE %s 
                   OR correo LIKE %s 
                   OR nss LIKE %s
                """
                param = f"%{busqueda.termino}%"
                cursor.execute(query, (param, param, param, param, param, param, param))

            empleados = cursor.fetchall()
            return empleados
        finally:
            cursor.close()


# Endpoint para información de catálogos
@app.get("/catalogos/{catalogo}")
async def get_catalogo(catalogo: str, current_user: dict = Depends(get_current_user)):
    # Mapeo de nombres de catálogos a tablas
    catalogos_permitidos = {
        "sexo": "Sexo",
        "estado_civil": "Estado_Civil",
        "tipo_contrato": "Tipo_Contrato",
        "departamento": "Departamento",
        "puesto": "Puesto",
        "turno": "Turno",
        "sucursal": "Sucursal",
        "roles": "Roles"
    }

    if catalogo not in catalogos_permitidos:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Catálogo no válido. Opciones: {', '.join(catalogos_permitidos.keys())}"
        )

    # Usando context manager para manejar la conexión automáticamente
    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True, prepared=True)
        try:
            cursor.execute(f"SELECT * FROM {catalogos_permitidos[catalogo]}")
            items = cursor.fetchall()
            return items
        finally:
            cursor.close()


def print_endpoints(host_ip="54.145.241.91"):
    """Imprime todos los endpoints disponibles en la API con sus descripciones."""
    print("\n" + "=" * 80)
    print(f"API de Empleados - Endpoints disponibles en http://{host_ip}:8000")
    print("=" * 80)

    # Autenticación
    print("\n-- AUTENTICACIÓN --")
    print(f"POST http://{host_ip}:8000/token")
    print("  Descripción: Obtener token de autenticación")
    print("  Cuerpo: {'username': 'correo@ejemplo.com', 'password': 'contraseña'}")

    # Empleados
    print("\n-- GESTIÓN DE EMPLEADOS --")
    print(f"GET http://{host_ip}:8000/empleados/")
    print("  Descripción: Obtiene la lista de todos los empleados")
    print("  Parámetros query opcionales: skip, limit")

    print(f"GET http://{host_ip}:8000/empleados/{{empleado_id}}")
    print("  Descripción: Obtiene los detalles de un empleado específico por su ID")

    print(f"POST http://{host_ip}:8000/empleados/")
    print("  Descripción: Crea un nuevo empleado")
    print("  Cuerpo: Objeto JSON con los datos del empleado")

    print(f"PUT http://{host_ip}:8000/empleados/{{empleado_id}}")
    print("  Descripción: Actualiza la información de un empleado existente")
    print("  Cuerpo: Objeto JSON con los datos actualizados")

    print(f"DELETE http://{host_ip}:8000/empleados/{{empleado_id}}")
    print("  Descripción: Elimina un empleado por su ID")

    print(f"POST http://{host_ip}:8000/empleados/buscar/")
    print("  Descripción: Busca empleados por diferentes criterios")
    print("  Cuerpo: {'termino': 'texto a buscar', 'campo': 'campo_opcional'}")

    # Catálogos
    print("\n-- CATÁLOGOS --")
    print(f"GET http://{host_ip}:8000/catalogos/{{catalogo}}")
    print("  Descripción: Obtiene los datos de un catálogo específico")
    print("  Catálogos disponibles: sexo, estado_civil, tipo_contrato, departamento, puesto, turno, sucursal, roles")

    # Documentación
    print("\n-- DOCUMENTACIÓN --")
    print(f"GET http://{host_ip}:8000/docs")
    print("  Descripción: Interfaz Swagger para probar y explorar la API")

    print(f"GET http://{host_ip}:8000/redoc")
    print("  Descripción: Documentación alternativa de la API en formato ReDoc")

    print("\n-- NOTA --")
    print("  Todos los endpoints (excepto documentación) requieren autenticación con token Bearer:")
    print("  Header: Authorization: Bearer tu_token_aquí")
    print("=" * 80 + "\n")


# Modificar la sección de punto de entrada para incluir la impresión de endpoints
if __name__ == "__main__":
    # Usar la dirección IP fija de tu instancia EC2
    ip_publica = "54.145.241.91"

    # Imprimir los endpoints
    print_endpoints(ip_publica)

    # Iniciar el servidor
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)