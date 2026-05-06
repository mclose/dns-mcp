from .server import create_server

if __name__ == "__main__":
    create_server().run(transport="streamable-http")
