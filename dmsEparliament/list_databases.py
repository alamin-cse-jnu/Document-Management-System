# Save as list_databases.py

import MySQLdb
import sys

try:
    # Try to connect to the MySQL/MariaDB server (without specifying a database)
    connection = MySQLdb.connect(
        host='127.0.0.1',
        user='root',
        passwd='',
        port=3307
    )
    
    cursor = connection.cursor()
    print("Successfully connected to the database server!")
    
    # List all databases
    cursor.execute("SHOW DATABASES")
    databases = cursor.fetchall()
    
    print("\nAvailable databases:")
    for db in databases:
        print(f"- {db[0]}")
    
    # Close connections
    cursor.close()
    connection.close()
    
except MySQLdb.Error as e:
    print(f"Error connecting to the database server: {e}")
    sys.exit(1)