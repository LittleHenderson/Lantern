"""A chat app that calls a model and a payment API: Lantern's AI-app sample."""
import os
import subprocess

from fastapi import FastAPI, Request
from openai import OpenAI

from .store import save_message

app = FastAPI()
client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))


@app.post("/api/chat")
async def chat(request: Request):
    body = await request.json()
    answer = ask_model(body["message"])
    save_message(body["message"], answer)
    return {"answer": answer}


@app.post("/api/agent/run")
async def run_tool(request: Request):
    body = await request.json()
    response = client.chat.completions.create(model="gpt-4o-mini", messages=[{"role": "user", "content": body["task"]}])
    command = response.choices[0].message.content
    subprocess.run(command, shell=True)
    return {"ran": command}


@app.post("/api/checkout")
async def checkout(request: Request):
    user = current_user(request)
    if not user:
        return {"error": "login required"}
    return create_charge(user)


def ask_model(text: str) -> str:
    response = client.chat.completions.create(model="gpt-4o-mini", messages=[{"role": "user", "content": text}], max_tokens=300)
    return response.choices[0].message.content


def create_charge(user: str):
    import stripe
    return stripe.PaymentIntent.create(amount=500, currency="usd", metadata={"user": user})


def current_user(request: Request) -> str:
    return request.cookies.get("session", "")
