import os

def load_hassh_database(file_path):
    database = {}
    with open(file_path, "r") as file:
        for line in file:
            if not line.strip():
                continue
            parts = line.split(" ", 1)
            hassh = parts[0].strip()
            description = parts[1].strip() if len(parts) > 1 else "Unknown"
            database[hassh] = description
    return database

def validate_hassh(hassh, database):
    return database.get(hassh, "HASSH no encontrado en la base de datos") 

db_file = "hasshdb"
captures_dir = ""

hassh_database = load_hassh_database(db_file)

capture_files = [os.path.join(captures_dir, f) for f in os.listdir(captures_dir) if f.endswith(".pcapng")]

for capture_file in capture_files:
    print(f"\n\033[34mProcesando captura: {capture_file}\033[0m")
    
    os.system(f"python3 fatt/fatt.py -r {capture_file} -p -j > output_hassh.txt")
    
    with open("output_hassh.txt", "r") as f:
        for line in f:
            if "hassh=" in line:
                client_hassh = line.split("hassh=")[1].split(" ")[0]
                client_result = validate_hassh(client_hassh, hassh_database)
                print(f"\033[32mClient HASSH:\033[0m {client_hassh} -> {client_result}")
            if "hasshS=" in line:
                server_hassh = line.split("hasshS=")[1].split(" ")[0]
                server_result = validate_hassh(server_hassh, hassh_database)
                print(f"\033[32mServer HASSH:\033[0m {server_hassh} -> {server_result}")
