from flask import Flask
from flask import request
from flask import Response

import time
import MySQLdb
import json

app = Flask(__name__)
db  = MySQLdb.connect("maindb", "root", "password")
MAIN_DB = db.cursor()

@app.route("/")
def hello():
    #curl -i http://$Server_IP:$Server_Port/
    return "<H1>Welcome to Python </H1>Checkpoint Date/Time: "+time.strftime("%c")+"\n"

@app.route("/init")
def init():
    #curl -i http://$Server_IP:$Server_Port/init
    MAIN_DB.execute("drop database if exists account")
    MAIN_DB.execute("create database account")
    MAIN_DB.execute("use account")
    sql = """create table users(
    ID int,
    USER varchar(20),
    DESCRIPTION varchar(250)
    )"""
    MAIN_DB.execute(sql)
    db.commit()
    return "## Database create new account table done ##\n"

@app.route("/users/insertuser", methods=['POST'])
def insertuser():
    req_json = request.get_json()
    #curl -i -H "Content-Type: application/json" -X POST -d '{"uid": "3", "user": "jimmy", "description": "security"}' $Server_IP:$Server_Port/users/insertuser
    sql = """insert into account.users(ID, USER, DESCRIPTION) values (%s, %s, %s)"""
    MAIN_DB.execute( sql, (req_json["uid"], req_json["user"], req_json["description"]) )
    db.commit()
    return Response(" ## record was added ## \n", status=200, mimetype='application/json')

@app.route("/users/<uid>")
def getuser(uid):
    #curl -i http://$Server_IP:$Server_Port/users/2
    MAIN_DB.execute("select user from account.users where id="+ str(uid))
    data = MAIN_DB.fetchone()
    if data:
        return (str(data[0])+"\n")
    else:
        return ("## not found ##")

@app.route("/users/removeuser/<uid>")
def deluser(uid):
    #curl -i http://$Server_IP:$Server_Port/users/removeuser/4
    MAIN_DB.execute("delete from account.users where id="+ str(uid))
    db.commit()
    return Response(" ## record was deleted ##\n", status=200, mimetype="application/json")

if __name__ == "__main__":
  app.run(host="0.0.0.0", port=5000, debug=True)
