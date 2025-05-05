# Updated script to create database on port 3306
import MySQLdb

connection = MySQLdb.connect(
    host='127.0.0.1',
    user='root',
    passwd='',
    port=3306  # Changed from 3307 to 3306
)

cursor = connection.cursor()
cursor.execute("DROP DATABASE IF EXISTS eparliament_dms")
cursor.execute("CREATE DATABASE eparliament_dms CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci")
print("Created database 'eparliament_dms' on port 3306")
cursor.close()
connection.close()