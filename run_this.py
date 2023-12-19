import subprocess
import os

def run_server():
    webapp_dir = os.path.join(os.path.dirname(__file__), 'webapp')
    os.chdir(webapp_dir)

    subprocess.run(['python', 'manage.py', 'runserver'])

if __name__ == "__main__":
    run_server()