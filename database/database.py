from pymongo import MongoClient

client = MongoClient("mongodb://localhost:27017")
database = client["gold_pro"]

users = database["users"]