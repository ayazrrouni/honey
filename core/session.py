def new_session(user="root", fs=None):
    home = "/root" if user == "root" else f"/home/{user}"
    return {
        "user": user,
        "cwd": home,
        "history": [],
        "fs": fs if fs else {"/": {}}
    }
