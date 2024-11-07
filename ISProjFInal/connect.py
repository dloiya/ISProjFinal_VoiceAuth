from pymongo import MongoClient
from pymongo.server_api import ServerApi

def connect():
    uri = "mongodb+srv://isprojectmit2024:NbedSBMCTUiiohtm@cluster0.cyqjo.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
    client = MongoClient(uri, server_api=ServerApi('1'))
    try:
        client.admin.command('ping')
        print("Pinged your deployment. You successfully connected to MongoDB!")
        return client
    except Exception as e:
        print(e)

client = connect()

def getdb():
    db = client["userdata"]
    return db