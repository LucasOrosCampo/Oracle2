from fastapi import FastAPI
from data.database import init_db
from api.user.user_router import user_router
import uvicorn

app = FastAPI()
app.include_router(user_router, tags=["Users"])


@app.get("/health")
async def root():
    return {"hello": "i am healthy"}


if __name__ == "__main__":
    init_db(drop_existing=False)
    uvicorn.run(app, host="0.0.0.0", port=7999)
