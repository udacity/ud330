# Restaurants and Menus

The first step is to setup the `.env` file to hold all of the environment variables that are needed to connect to the APIs.  To do so, run `cp .env.example .env`, which will copy the example file to the .env file.  This file is not committed to the Git repo.  

The version of Python is `3.6.1`, which is shown in the `.python-version` file.

After signing up for an app on facebook and google, fill in the values in their appropriate places in the `.env` file.  These will automatically cascade to the rest of the app.

The database used by default is restaurantmenuwithusers.db.  To change to another database engine, look in the `database_setup.py` file and change the engine to whatever is appropriate for your use case.

To start using the program, run:
```shell
pip install -r requirements.txt
```

This will install all of the dependencies.

To re-run the base seeds, run `python lotsofmenus.py`.

To start up the app, run either:

```shell
export FLASK_APP=project.py
flask run
```

Or 
```shell
python project.py
```