from fastapi import APIRouter

router = APIRouter(prefix="/jobs")


@router.get("/")
def get_jobs():
    return {"message": "Get all jobs"}
