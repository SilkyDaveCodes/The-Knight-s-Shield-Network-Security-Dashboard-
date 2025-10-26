from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import snowflake.connector
import os
from dotenv import load_dotenv

load_dotenv()
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def connect_snowflake():
    return snowflake.connector.connect(
        user=os.getenv("SNOW_USER"),
        password=os.getenv("SNOW_PASSWORD"),
        account=os.getenv("SNOW_ACCOUNT"),
        warehouse=os.getenv("SNOW_WAREHOUSE"),
        database=os.getenv("SNOW_DATABASE"),
        schema=os.getenv("SNOW_SCHEMA")
    )

@app.get("/api/packets")
def get_packets():
    conn = connect_snowflake()
    cur = conn.cursor()

    cur.execute(
        """
        SELECT SRC, DST, DST_PORT, PROTO, LEN, HOST_SNI,
        SUSPICIOUS_SCORE, REASON
        FROM PACKETS
        ORDER BY TS DESC
        LIMIT 20;
        """
        )
    columns = [desc[0] for desc in cur.description]
    data = [dict(zip(columns, row)) for row in cur.fetchall()]
    cur.close()
    conn.close()
    return data