import time
from datetime import timedelta
from typing import List

from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession



from embrapa import database
from embrapa.import_embrapa import import_embrapa
from embrapa.repository import (
    exportacaoRepository,
    importacaoRepository,
    processamentoRepository,
    producaoRepository,
)

from embrapa.schemas.exportacao import Exportacao
from embrapa.schemas.importacao import Importacao
from embrapa.schemas.processamento import Processamento
from embrapa.schemas.producao import Producao

from jwt.exceptions import JWTError


import jwt
from passlib.context import CryptContext


app = FastAPI()

# Secret key para assinar os JWTs. 
SECRET_KEY = "407ce64631e29774f76c6f6a1db3c21a49011c3ea5c15b54c560672d7f2e836b"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Configuração do contexto de segurança para lidar com senhas
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# Método para verificar a senha
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


# Método para gerar hash da senha
def get_password_hash(password):
    return pwd_context.hash(password)

# Modelo de usuário de exemplo
class User:
    def __init__(self, username, password):
        self.username = username
        self.password_hash = get_password_hash(password)
        

# Usuário de exemplo
fake_users_db = {
    "user1": User(username="user1", password="password1"),
    "user2": User(username="user2", password="password2"),
}


# Função para autenticar o usuário
def authenticate_user(username: str, password: str):
    user = fake_users_db.get(username)
    if not user or not verify_password(password, user.password_hash):
        return False
    return user


# Função para criar um token de acesso JWT
def create_access_token(data: dict, expires_delta: int = None):
    to_encode = data.copy()
    if expires_delta:
        expire = time.time() + expires_delta
    else:
        expire = time.time() + (60 * ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


# Dependência OAuth2 para autenticar usuários
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")


# Rota para autenticar usuários e gerar token de acesso JWT
@app.post("/token")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Credenciais inválidas",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


# Função para obter uma instância de sessão assíncrona do banco de dados
async def get_db():
    async with database.AsyncSessionLocal() as session:
        yield session
        
        
@app.get("/api/protected_route")
async def protected_route(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Não autorizado")
        # Lógica adicional para proteção da rota aqui
        return {"message": "Rota protegida"}
    except JWTError:
        raise HTTPException(status_code=401, detail="Não autorizado")


@app.get('/api/importar_csv_site_embrapa')
def importa_csv():
    try:
        import_embrapa.import_csv_site_embrapa()
        return 'Arquivos CSVs importados com sucesso do site da Embrapa!'
    except TimeoutError:
        # Tratamento para tempo limite
        time.sleep(5)  # Espera 5 segundos e tenta novamente
        import_embrapa.import_csv_site_embrapa()
        return 'Tentativa de importação de arquivos CSVs no site da EMBRAPA excedeu o tempo limite!'


@app.get('/api/importar_csv_arquivos')
def importa_arquivo_csv():
    try:
        import_embrapa.import_csv_files_embrapa()
        return 'Arquivos CSVs importados com sucesso!'
    except TimeoutError:
        # Tratamento para tempo limite
        time.sleep(5)  # Espera 5 segundos e tenta novamente
        import_embrapa.import_csv_files_embrapa()
        return (
            'Tentativa de importação dos arquivos CSVs excedeu o tempo limite!'
        )


# Função para obter uma instância de sessão assíncrona do banco de dados
async def get_db():
    async with database.AsyncSessionLocal() as session:
        yield session


@app.get('/api/producao/', response_model=List[Producao])
async def get_producoes(db: database.AsyncSessionLocal = Depends(get_db)):
    producoes = await producaoRepository.get_producoes(db)
    return producoes


@app.get('/api/processamento/', response_model=List[Processamento])
async def get_procesamentos(db: database.AsyncSessionLocal = Depends(get_db)):
    processamentos = await processamentoRepository.get_processamentos(db)
    return processamentos


@app.get('/api/importacao/', response_model=List[Importacao])
async def get_importacoes(db: database.AsyncSessionLocal = Depends(get_db)):
    importacoes = await importacaoRepository.get_importacoes(db)
    return importacoes


@app.get('/api/exportacao/', response_model=List[Exportacao])
async def get_exportacoes(db: database.AsyncSessionLocal = Depends(get_db)):
    exportacoes = await exportacaoRepository.get_exportacoes(db)
    return exportacoes

