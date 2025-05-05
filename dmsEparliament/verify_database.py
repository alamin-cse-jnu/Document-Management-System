# Save as verify_database.py

import MySQLdb
import sys

try:
    # First connect without a database to make sure server connection works
    connection = MySQLdb.connect(
        host='127.0.0.1',
        user='root',
        passwd='',
        port=3307
    )
    print("Server connection successful")
    connection.close()
    
    # Now try to connect to the specific database
    db_connection = MySQLdb.connect(
        host='127.0.0.1',
        user='root',
        passwd='',
        port=3307,
        db='eparliament_dms'
    )
    
    print("Successfully connected to 'eparliament_dms' database!")
    
    # Create a test table to verify write permissions
    cursor = db_connection.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS test_table (id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(255))")
    cursor.execute("INSERT INTO test_table (name) VALUES ('Test data')")
    db_connection.commit()
    print("Successfully created table and inserted data")
    
    # Clean up
    cursor.execute("DROP TABLE test_table")
    db_connection.commit()
    print("Successfully cleaned up test table")
    
    cursor.close()
    db_connection.close()
    
except MySQLdb.Error as e:
    print(f"Error: {e}")
    print("\nDetailed debugging information:")
    print(f"Error code: {e.args[0]}")
    print(f"Error message: {e.args[1]}")
    sys.exit(1)