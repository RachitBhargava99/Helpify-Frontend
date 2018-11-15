from frontend import create_app

app = create_app()

if __name__ == '__main__':

    app.run(host = '127.0.0.2', port = 80, debug = True)
