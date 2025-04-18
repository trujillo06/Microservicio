from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timedelta, date
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
# Lista de orígenes permitidos que siempre deberían funcionar
allowed_origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173"
]

# Obtener orígenes adicionales del archivo .env
extra_origins = os.getenv("ALLOWED_ORIGINS", "")
if extra_origins and extra_origins != "*":
    # Añadir orígenes adicionales específicos
    allowed_origins.extend(extra_origins.split(","))

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configuración de conexión a base de datos utilizando pool de conexiones
db_config = {
    "host": os.getenv("DB_HOST"),
    "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASSWORD"),
    "database": os.getenv("DB_NAME"),
    "port": int(os.getenv("DB_PORT", "3306")),
}

# Crear un pool de conexiones para mejorar rendimiento y seguridad
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


# Funciones auxiliares para convertir entre datetime y string
def parse_date(date_str):
    """Convierte una cadena de fecha en objeto date"""
    if not date_str:
        return None
    try:
        return datetime.strptime(date_str, '%Y-%m-%d').date()
    except ValueError:
        raise ValueError('Formato de fecha inválido. Use YYYY-MM-DD')


def format_date(date_obj):
    """Convierte un objeto date en cadena con formato ISO"""
    if not date_obj:
        return None
    return date_obj.isoformat()


# Modelos de datos mejorados con validaciones
class EmpleadoBase(BaseModel):
    nombre: str = Field(..., min_length=2, max_length=100)
    apellido_paterno: str = Field(..., min_length=2, max_length=100)
    apellido_materno: Optional[str] = Field(None, min_length=2, max_length=100)
    fecha_nacimiento: date  # Cambiado de str a date
    sexo: int = Field(..., ge=1)
    estado_civil: int = Field(..., ge=1)
    direccion: Optional[str] = Field(None, max_length=255)
    telefono: Optional[str] = Field(None, max_length=20)
    curp: str = Field(..., min_length=18, max_length=18)
    correo: EmailStr
    rfc: str = Field(..., min_length=12, max_length=13)
    nss: str = Field(..., min_length=11, max_length=11)
    foto: Optional[str] = None
    fecha_ingreso: date  # Cambiado de str a date
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

    @field_validator('telefono')
    @classmethod
    def validate_telefono(cls, v):
        if v and not re.match(r'^\+?[0-9]{10,15}$', v):
            raise ValueError('Formato de teléfono inválido')
        return v

    # Configuración del modelo
    class Config:
        json_encoders = {
            date: lambda dt: dt.isoformat() if dt else None
        }


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
        json_encoders = {
            date: lambda dt: dt.isoformat() if dt else None
        }


class BusquedaEmpleado(BaseModel):
    termino: str = Field(..., min_length=1, max_length=100)
    campo: Optional[str] = Field(None, pattern=r'^[a-zA-Z_]+$')  # Cambiado regex por pattern


# Middleware para sanitizar consultas SQL
def sanitize_sql_input(value):
    if isinstance(value, str):
        # Eliminar caracteres que podrían ser usados en ataques
        sanitized = re.sub(r'[;\'"\\]', '', value)
        return sanitized
    return value


# Funciones para procesar datos antes de enviarlos a la base de datos y después de recibirlos
def process_employee_for_db(empleado_data):
    """Procesa los datos del empleado para la base de datos, convirtiendo objetos date a strings"""
    processed_data = empleado_data.copy()

    # Convertir objetos date a strings en formato MySQL
    if isinstance(processed_data.get('fecha_nacimiento'), date):
        processed_data['fecha_nacimiento'] = processed_data['fecha_nacimiento'].isoformat()

    if isinstance(processed_data.get('fecha_ingreso'), date):
        processed_data['fecha_ingreso'] = processed_data['fecha_ingreso'].isoformat()

    return processed_data


def process_db_employee(db_empleado):
    """Procesa los datos del empleado desde la base de datos, convirtiendo strings a objetos date"""
    if not db_empleado:
        return None

    processed_empleado = dict(db_empleado)

    # Convertir strings de fecha a objetos date
    for date_field in ['fecha_nacimiento', 'fecha_ingreso']:
        if date_field in processed_empleado and processed_empleado[date_field]:
            if isinstance(processed_empleado[date_field], str):
                processed_empleado[date_field] = parse_date(processed_empleado[date_field])
            elif isinstance(processed_empleado[date_field], datetime):
                processed_empleado[date_field] = processed_empleado[date_field].date()

    return processed_empleado


# Endpoints de empleados
@app.get("/empleados/", response_model=List[EmpleadoResponse])
async def get_empleados(skip: int = 0, limit: int = 100):
    # Validación adicional de parámetros
    if skip < 0 or limit < 1 or limit > 1000:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Parámetros de paginación inválidos"
        )

    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True, prepared=True)
        try:
            query = """
                SELECT * FROM Empleados
                ORDER BY id_empleado
                LIMIT %s OFFSET %s
                """
            cursor.execute(query, (limit, skip))
            empleados_raw = cursor.fetchall()

            # Procesar las fechas para cada empleado
            empleados = [process_db_employee(emp) for emp in empleados_raw]
            return empleados
        finally:
            cursor.close()


@app.get("/empleados/{empleado_id}", response_model=EmpleadoResponse)
async def get_empleado(empleado_id: int):
    if empleado_id <= 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="ID de empleado inválido"
        )

    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True, prepared=True)
        try:
            query = "SELECT * FROM Empleados WHERE id_empleado = %s"
            cursor.execute(query, (empleado_id,))
            empleado_raw = cursor.fetchone()
            if empleado_raw is None:
                raise HTTPException(status_code=404, detail="Empleado no encontrado")

            # Procesar las fechas
            empleado = process_db_employee(empleado_raw)
            return empleado
        finally:
            cursor.close()


@app.post("/empleados/", response_model=EmpleadoResponse, status_code=status.HTTP_201_CREATED)
async def create_empleado(empleado: EmpleadoCreate):
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

            # Preparar los campos para la inserción - procesando las fechas
            campos = empleado.model_dump(exclude_unset=True)
            campos = process_employee_for_db(campos)

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
            new_empleado_raw = cursor.fetchone()

            # Procesar las fechas
            new_empleado = process_db_employee(new_empleado_raw)

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
async def update_empleado(empleado_id: int, empleado_update: EmpleadoCreate):
    if empleado_id <= 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="ID de empleado inválido"
        )

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
            cursor.execute(query, (
                empleado_update.curp, empleado_update.correo, empleado_update.rfc, empleado_update.nss, empleado_id))
            if cursor.fetchone():
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Ya existe otro empleado con CURP, correo, RFC o NSS proporcionado"
                )

            # Preparar los campos para la actualización - procesando las fechas
            campos = empleado_update.model_dump(exclude_unset=True)
            campos = process_employee_for_db(campos)

            set_clause = ", ".join([f"{k} = %s" for k in campos.keys()])
            values = list(campos.values())
            values.append(empleado_id)  # Para la condición WHERE

            query = f"UPDATE Empleados SET {set_clause} WHERE id_empleado = %s"
            cursor.execute(query, values)
            conn.commit()

            # Recuperar el empleado actualizado
            cursor.execute("SELECT * FROM Empleados WHERE id_empleado = %s", (empleado_id,))
            updated_empleado_raw = cursor.fetchone()

            # Procesar las fechas
            updated_empleado = process_db_employee(updated_empleado_raw)

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
async def delete_empleado(empleado_id: int):
    if empleado_id <= 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="ID de empleado inválido"
        )

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
async def buscar_empleados(busqueda: BusquedaEmpleado):
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

            empleados_raw = cursor.fetchall()

            # Procesar las fechas para cada empleado
            empleados = [process_db_employee(emp) for emp in empleados_raw]
            return empleados
        finally:
            cursor.close()


# Endpoint para información de catálogos
@app.get("/catalogos/{catalogo}")
async def get_catalogo(catalogo: str):
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
    print("=" * 80 + "\n")


# Modificar la sección de punto de entrada para incluir la impresión de endpoints
if __name__ == "__main__":
    # Usar la dirección IP fija de tu instancia EC2
    ip_publica = "54.145.241.91"

    # Imprimir los endpoints
    print_endpoints(ip_publica)

    # Iniciar el servidor
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)