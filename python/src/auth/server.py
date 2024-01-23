import jwt, datetime, os
from flask import Flask, request
from flask_mysqldb import MySQL
#using Flask to create our server : Authentication using JWT

server = Flask(__name__)
mysql = MySQL(server)

#config
server.config["MYSQL_HOST"] = os.environ.get(("MYSQL_HOST")) #stores config variables
server.config["MYSQL_USER"] = os.environ.get(("MYSQL_USER")) 
server.config["MYSQL_PASSWORD"] = os.environ.get(("MYSQL_PASSWORD"))
server.config["MYSQL_DB"] = os.environ.get(("MYSQL_DB"))
server.config["MYSQL_PORT"] = os.environ.get(("MYSQL_PORT"))

@server.route("/login", methods=["POST"])
def login():
    auth = request.authorization
    if not auth:
        return "missing credentials", 401
    
    #check db for username and password
    cur = mysql.connection.cursor()
    res = cur.execute(
        "SELECT email, password FROM user WHERE email=%s", (auth.username,)
    )

    if res > 0:
        user_row = cur.fetchone() #this returns a tuple
        email = user_row[0]
        password = user_row[1]

        if auth.username != email or auth.password:
            return "invalid credentials", 401
        else:
            return createJWT(auth.username, os.environ.get("JWT_SECRET"), True)
    else:
        return "Invalid Credentials", 401

@server.route("/validate",method=["POST"])
def validate():
    encoded_jwt = request.headers["Authorization"]

    if not encoded_jwt:
        return "Missing credentials", 401
    
    encoded_jwt = encoded_jwt.split(" ")[1]

    try:
        decoded = jwt.decode(
            encoded_jwt, os.environ.get("JWT_SECRET"), algorithm=["HS256"]
        )
    except:
        return "Not authorized", 403
    
    return decoded, 200


def createJWT(username,secret, authz): #creates a JSON Web Token
    return jwt.encode(
        {
            "username": username,
            "exp": datetime.datetime.now(tz=datetime.timezone.utc)
            + datetime.timedelta(days=1),
            "iat": datetime.datetime.utcnow(),
            "admin": authz,
        },
        secret,
        algorithm="HS256",
    )

# flow is: user makes request to login route using credentials
# check if the user exists in db
# JWT returned on user authenticated. Will be used by user to make requests by api
# docker container will have its own ip address in which the server is contained
if __name__ == "__main__":
    server.run(host="0.0.0.0",  port=5000)
