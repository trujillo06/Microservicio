# main.py
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import List, Optional
from pydantic import BaseModel
import mysql.connector
import uvicorn
import os
from dotenv import load_dotenv

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
    allow_origins=["*"],  # En producción, especificar dominios concretos
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configuración de seguridad
SECRET_KEY = os.getenv("SECRET_KEY", "clave_secreta_para_jwt_cambiar_en_produccion")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Configuración de la base de datos
DB_CONFIG = {
    "host": "bcnppqqfmqxbm3apxjw8-mysql.services.clever-cloud.com",
    "user": "u9ohiy6yqnl12rzl",
    "password": "uewann11vk1iYOPQNYu6",
    "database": "bcnppqqfmqxbm3apxjw8",
    "port": 3306
}


# Modelos de datos
class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Optional[str] = None


class UserLogin(BaseModel):
    username: str
    password: str


class EmpleadoBase(BaseModel):
    nombre: str
    apellido_paterno: str
    apellido_materno: Optional[str] = None
    fecha_nacimiento: str
    sexo: int
    estado_civil: int
    direccion: Optional[str] = None
    telefono: Optional[str] = None
    curp: str
    correo: str
    rfc: str
    nss: str
    foto: Optional[str] = None
    fecha_ingreso: str
    tipo_contrato: int
    puesto: int
    departamento: int
    sucursal: int
    turno: int
    salario: float
    usuario: Optional[int] = None


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
        orm_mode = True


class BusquedaEmpleado(BaseModel):
    termino: str
    campo: Optional[str] = None  # nombre, correo, curp, rfc, etc.


# Configuración de autenticación
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


# Funciones de utilidad para la base de datos
def get_db_connection():
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        return conn
    except mysql.connector.Error as e:
        print(f"Error de conexión a la base de datos: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error de conexión a la base de datos"
        )


# Funciones de seguridad
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
    conn = get_db_connection()
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id_usuario, correo, rol FROM Usuarios WHERE correo = %s", (token_data.username,))
        user = cursor.fetchone()
        if user is None:
            raise credentials_exception
        return user
    finally:
        cursor.close()
        conn.close()


# Endpoints de autenticación
@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    conn = get_db_connection()
    try:
        cursor = conn.cursor(dictionary=True)
        # En un entorno real, la contraseña debería estar hasheada
        cursor.execute(
            "SELECT id_usuario, correo, contraseña, rol FROM Usuarios WHERE correo = %s",
            (form_data.username,)
        )
        user = cursor.fetchone()

        if not user or user["contraseña"] != form_data.password:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Usuario o contraseña incorrectos",
                headers={"WWW-Authenticate": "Bearer"},
            )

        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user["correo"], "role": user["rol"]},
            expires_delta=access_token_expires
        )
        return {"access_token": access_token, "token_type": "bearer"}
    finally:
        cursor.close()
        conn.close()


# Endpoints de empleados
@app.get("/empleados/", response_model=List[EmpleadoResponse])
async def get_empleados(current_user: dict = Depends(get_current_user), skip: int = 0, limit: int = 100):
    conn = get_db_connection()
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT * FROM Empleados
            ORDER BY id_empleado
            LIMIT %s OFFSET %s
            """,
            (limit, skip)
        )
        empleados = cursor.fetchall()
        return empleados
    finally:
        cursor.close()
        conn.close()


@app.get("/empleados/{empleado_id}", response_model=EmpleadoResponse)
async def get_empleado(empleado_id: int, current_user: dict = Depends(get_current_user)):
    conn = get_db_connection()
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM Empleados WHERE id_empleado = %s", (empleado_id,))
        empleado = cursor.fetchone()
        if empleado is None:
            raise HTTPException(status_code=404, detail="Empleado no encontrado")
        return empleado
    finally:
        cursor.close()
        conn.close()


@app.post("/empleados/", response_model=EmpleadoResponse, status_code=status.HTTP_201_CREATED)
async def create_empleado(empleado: EmpleadoCreate, current_user: dict = Depends(get_current_user)):
    conn = get_db_connection()
    try:
        cursor = conn.cursor(dictionary=True)

        # Verificar si ya existe un empleado con CURP, correo, RFC o NSS existente
        cursor.execute(
            """
            SELECT id_empleado FROM Empleados 
            WHERE curp = %s OR correo = %s OR rfc = %s OR nss = %s
            """,
            (empleado.curp, empleado.correo, empleado.rfc, empleado.nss)
        )

        if cursor.fetchone():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Ya existe un empleado con CURP, correo, RFC o NSS proporcionado"
            )

        # Preparar los campos para la inserción
        campos = empleado.dict()
        placeholder_names = ", ".join(campos.keys())
        placeholder_values = ", ".join(["%s"] * len(campos))

        query = f"INSERT INTO Empleados ({placeholder_names}) VALUES ({placeholder_values})"
        cursor.execute(query, list(campos.values()))
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
        conn.close()


@app.put("/empleados/{empleado_id}", response_model=EmpleadoResponse)
async def update_empleado(empleado_id: int, empleado_update: EmpleadoCreate,
                          current_user: dict = Depends(get_current_user)):
    conn = get_db_connection()
    try:
        cursor = conn.cursor(dictionary=True)

        # Verificar si el empleado existe
        cursor.execute("SELECT id_empleado FROM Empleados WHERE id_empleado = %s", (empleado_id,))
        if not cursor.fetchone():
            raise HTTPException(status_code=404, detail="Empleado no encontrado")

        # Verificar que no haya conflictos con otros empleados
        cursor.execute(
            """
            SELECT id_empleado FROM Empleados 
            WHERE (curp = %s OR correo = %s OR rfc = %s OR nss = %s) AND id_empleado != %s
            """,
            (empleado_update.curp, empleado_update.correo, empleado_update.rfc, empleado_update.nss, empleado_id)
        )
        if cursor.fetchone():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Ya existe otro empleado con CURP, correo, RFC o NSS proporcionado"
            )

        # Preparar los campos para la actualización
        campos = empleado_update.dict()
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
        conn.close()


@app.delete("/empleados/{empleado_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_empleado(empleado_id: int, current_user: dict = Depends(get_current_user)):
    conn = get_db_connection()
    try:
        cursor = conn.cursor()

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
        conn.close()


@app.post("/empleados/buscar/", response_model=List[EmpleadoResponse])
async def buscar_empleados(busqueda: BusquedaEmpleado, current_user: dict = Depends(get_current_user)):
    conn = get_db_connection()
    try:
        cursor = conn.cursor(dictionary=True)

        # Construir la consulta según el campo especificado
        if busqueda.campo:
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
        conn.close()


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

    conn = get_db_connection()
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(f"SELECT * FROM {catalogos_permitidos[catalogo]}")
        items = cursor.fetchall()
        return items
    finally:
        cursor.close()
        conn.close()


def print_endpoints(host_ip):
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
    # Obtener la IP pública (esto es solo un ejemplo, deberías obtenerla de forma dinámica)
    import requests

    try:
        # Intentar obtener la IP pública
        ip_publica = requests.get('https://api.ipify.org').text
    except:
        # Si falla, usar un placeholder
        ip_publica = "tu-ip-publica-ec2"

    # Imprimir los endpoints
    print_endpoints(ip_publica)

    # Iniciar el servidor
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)