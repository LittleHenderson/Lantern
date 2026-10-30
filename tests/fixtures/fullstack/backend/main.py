from fastapi import APIRouter, Depends, FastAPI

app = FastAPI()
router = APIRouter(prefix="/items")


def get_current_user():
    return {"id": 1}


def save_item(item_id, data):
    return {"id": item_id, **data}


@router.get("/")
def list_items():
    return []


@router.put("/{item_id}")
def update_item(item_id: int, data: dict, user=Depends(get_current_user)):
    return save_item(item_id, data)


@router.get("/{item_id}")
def read_item(item_id: int):
    return {"id": item_id}


@router.get("/mine")
def my_items(user=Depends(get_current_user)):
    return []


app.include_router(router, prefix="/api")
