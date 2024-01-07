import mysql.connector


def query_hashed_db(file_hashes, db_name="DB", table_name="words", column_name="word"):
    """Query the local MySQL database using LIKE operator with capitalized hashes, printing information about each file."""
    benign_hashes = set()
    try:
        # 2.  Connect to the MySQL database
        conn = mysql.connector.connect(
            host="localhost", user="root", password="root", database=db_name
        )
        cursor = conn.cursor()
        for file_name, file_hash in file_hashes:
            # 2.  Capitalize the hash before querying
            file_hash_upper = file_hash.upper()
            # 3.  Prepare the query using the LIKE operator
            query = f"SELECT * FROM {table_name} WHERE {column_name} LIKE %s"
            like_pattern = f"%{file_hash_upper}%"
            cursor.execute(query, (like_pattern,))
            # 4.  Notify for hashes that were found and add them to the benign list
            if cursor.fetchone():
                benign_hashes.add(file_hash)
                print(
                    f"{file_name}, hash: {file_hash_upper} | successfully found in {db_name}"
                )
            else:
                print(f"{file_name}, hash: {file_hash_upper} | not found in {db_name}")
        conn.close()
    except mysql.connector.Error as e:
        print(f"Database error: {e}")
    # 5.  Return all hashes not in the benign_hashes list to the file_hashes array for further analysis
    return [fh for fh in file_hashes if fh[1] not in benign_hashes]


def single_query_hashed_db(md5_hash, db_name="DB", table_name="words", column_name="word"):
    benign_hashes = set()
    try:
        # 2.  Connect to the MySQL database
        conn = mysql.connector.connect(
            host="localhost", user="root", password="root", database=db_name
        )
        cursor = conn.cursor()
        md5_hash_upper = md5_hash.upper()
        # 3.  Prepare the query using the LIKE operator
        query = f"SELECT * FROM {table_name} WHERE {column_name} LIKE %s"
        like_pattern = f"%{md5_hash_upper}%"
        cursor.execute(query, (like_pattern,))
        # 4.  Notify for hashes that were found and add them to the benign list
        if cursor.fetchone():
            benign_hashes.add(md5_hash)
            print(f"MD5 hash: {md5_hash_upper} | successfully found in {db_name}")
        else:
            print(f"MD5 hash: {md5_hash_upper} | not found in {db_name}")
    except mysql.connector.Error as e:
        print(f"Database error: {e}")