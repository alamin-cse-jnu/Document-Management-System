# Save as test_db.py in your project root

import MySQLdb
import sys

try:
    # Try to connect to the database
    connection = MySQLdb.connect(
        host='127.0.0.1',
        user='root',
        passwd='',
        port=3307,
        db='eparliament_dms'
    )
    
    cursor = connection.cursor()
    print("Successfully connected to the database!")
    
    # Check if we can execute a simple query
    cursor.execute("SELECT 1")
    result = cursor.fetchone()
    print(f"Query result: {result}")
    
    # Close connections
    cursor.close()
    connection.close()
    
except MySQLdb.Error as e:
    print(f"Error connecting to the database: {e}")
    sys.exit(1)