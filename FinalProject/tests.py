# flask_tracking/users/tests.py
from flask import url_for
from flask import session as login_session
from flask.ext.testing import TestCase
from flask import Flask
import flask.ext.testing

from flask.ext.sqlalchemy import SQLAlchemy

from finalproject import app
from finalproject import init
from finalproject import newMenuItem
from finalproject import set_db_session, set_login_session_user_id
# from finalproject import session
# import db

#!flask/bin/python
import os
import unittest
import json

# from config import BASE_DIR
from database_setup import User
from database_setup import Restaurant
from database_setup import MenuItem

CLIENT_ID = json.loads(
open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Restaurant Menu Application"

# Base.metadata.bind = engine

# DBSession = sessionmaker(bind=engine)
# session = DBSession()


class ModelsTestCase(TestCase):
    SQLALCHEMY_DATABASE_URI = "sqlite://tests.db"
    TESTING = True
    def create_app(self):
        app = Flask(__name__)
        app.config['SECRET_KEY'] = 'super_secret_key'
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tests.db'
        app.config['SESSION_TYPE'] = 'filesystem'
        self.db = SQLAlchemy(app)
        app.debug = True
        with app.test_client().session_transaction() as sess:
            sess['user_id'] = 1
        with app.test_request_context():
            set_login_session_user_id(1)
        return app

    def setUp(self):
        self.db.create_all()
        self.client = self.app.test_client()
        set_db_session(self.db.session)

    def tearDown(self):
        self.db.session.remove()
        self.db.drop_all()

    def test_make_unique_nickname(self):
        u = User(name='john', email='john@example.com', picture="")
        self.db.session.add(u)
        self.db.session.commit()
        nickname = User.make_unique_nickname('john', self.db.session)
        assert nickname != 'john'
        u = User(name=nickname, email='susan@example.com', picture="")
        self.db.session.add(u)
        self.db.session.commit()
        nickname2 = User.make_unique_nickname('john', self.db.session)
        assert nickname2 != 'john'
        assert nickname2 != nickname

class UserViewsTests(TestCase):
    SQLALCHEMY_DATABASE_URI = "sqlite://tests.db"
    TESTING = True
    def create_app(self):
        app = Flask(__name__)
        app.config['SECRET_KEY'] = 'super_secret_key'
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tests.db'
        app.config['SESSION_TYPE'] = 'filesystem'
        self.db = SQLAlchemy(app)
        app.debug = True
        with app.test_client().session_transaction() as sess:
            sess['user_id'] = 1
        with app.test_request_context():
            set_login_session_user_id(1)
            print("In create_app, login_session: {}".format(login_session))
        return app

    def setUp(self):
        self.db.create_all()
        set_db_session(self.db.session)
        # self.client = self.app.test_client()

    def tearDown(self):
        self.db.session.remove()
        self.db.drop_all()


    def test_users_can_login(self):
        u = User(name='joe', email='joe@example.com', picture="12345")
        self.db.session.add(u)
        self.db.session.commit()

        # response = self.app.post(url_for('auth.login'), data={'email': 'joe@joes.com', 'picture': '12345'})
        response = app.test_client(self).get('/')
        print("response /: {}".format(response.__dict__))
        assert response.status_code == 200
        # data = json.loads(response.data)
        # print("data: {}".format(data))
        response = app.test_client(self).get('/login')
        print("response /login: {}".format(response.__dict__))
        assert response.status_code == 200

    def test_add_menuitem(self):
        u = User(name='john', email='john@example.com', picture="")
        self.db.session.add(u)
        self.db.session.commit()
        # newMenuItem(r.id)
        with app.test_client() as c:
            with c.session_transaction() as sess:
                sess['user_id'] = 1
            response = c.post('/restaurant/1/menu/new/', data=dict(name = 'yummy dog', description= 'you must try this', price= 1, course = 'dessert'), follow_redirects=True)
        print("response: {}".format(response.__dict__))
        print("response[status]: {}".format(response.status_code))
        print("menu item count: {}".format(self.db.session.query(MenuItem).count()))
        lastItem = self.db.session.query(MenuItem).order_by(MenuItem.id.desc()).first()
        print("menu item last: {}".format(lastItem.__dict__))
        assert lastItem.name == 'yummy dog'

    def test_add_restaurant(self):
        u = User(name='john', email='john@example.com', picture="")
        self.db.session.add(u)
        self.db.session.commit()
        # newMenuItem(r.id)
        # app.session_transaction()['user_id'] = 1
        with app.test_client() as c:
            with c.session_transaction() as sess:
                sess['user_id'] = 1
            # print ("In test_add_restaurant: {}".format(app.login_session))
            # app.login_session['user_id'] = 1
            print ("In test_add_restaurant: {}".format(login_session))
            response = c.post('/restaurant/new/', data={'name': 'soups r us'}, follow_redirects=True)
        print("response: {}".format(response.__dict__))
        print("response[status]: {}".format(response.status_code))
        assert self.db.session.query(Restaurant).all() != None

if __name__ == '__main__':
    unittest.main()

