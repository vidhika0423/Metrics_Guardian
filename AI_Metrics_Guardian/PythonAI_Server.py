import socket
import json

import os
import os
from dotenv import load_dotenv
load_dotenv()
groq_api_key=os.getenv("GROQ_API_KEY")

# model
from langchain_groq import ChatGroq
model=ChatGroq(model="Gemma2-9b-It",groq_api_key=groq_api_key)

HOST = '127.0.0.1'
PORT = 12345

def analyze_metrics_with_groq(metrics):
    prompt = f"""
    You are an AI system monitoring computer system metrics. The following system metrics were collected:

    {json.dumps(metrics, indent=2)}

    Please analyze the metrics and tell if there is any anomaly or issue in the system performance. If everything looks good, say so.
    respons eshould be human reable and in proper format like:
    CPU: analysis of CPU,
    Disk: analysis of disk, etc...
    """

    response = model.invoke(prompt)
    return response.content.strip()

def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"Listening on {HOST}:{PORT}")
        
        conn, addr = s.accept()
        with conn:
            print(f"Connected by {addr}")
            data = conn.recv(4096)
            if data:
                metrics = json.loads(data.decode())
                print("Received JSON:", json.dumps(metrics, indent=2))

                # Analyze the received metrics with OpenAI API
                analysis = analyze_metrics_with_groq(metrics)

                response = {"analysis": analysis}
                conn.sendall(json.dumps(response).encode())
                print("Analysis sent to client.")

if __name__ == "__main__":
    start_server()
