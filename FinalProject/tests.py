# flask_tracking/users/tests.py
from flask import url_for
from flask import session as login_session

from sqlalchemy import create_engine, asc
from sqlalchemy.orm import scoped_session, sessionmaker

from finalproject import app
from finalproject import init_db2
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


class TestCase(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        self.session, self.scoped_session = init_db2('sqlite:///tests.db')
        # app.config['WTF_CSRF_ENABLED'] = False
        # app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(BASE_DIR, 'test.db')
        self.app = app.test_client()
        app.secret_key = 'super_secret_key'
        app.debug = True
        set_db_session(self.session)
        with self.app.session_transaction() as sess:
            sess['user_id'] = 1
            print("session: {}".format(sess.__dict__))

        # db.create_all()

    def tearDown(self):
        self.session.close()
        self.scoped_session.remove()
        # Base.metadata.drop_all()


    def test_make_unique_nickname(self):
        u = User(name='john', email='john@example.com', picture="")
        self.session.add(u)
        self.session.commit()
        nickname = User.make_unique_nickname('john', self.session)
        assert nickname != 'john'
        u = User(name=nickname, email='susan@example.com', picture="")
        self.session.add(u)
        self.session.commit()
        nickname2 = User.make_unique_nickname('john', self.session)
        assert nickname2 != 'john'
        assert nickname2 != nickname

    def test_add_menuitem(self):
        u = User(name='john', email='john@example.com', picture="")
        self.session.add(u)
        self.session.commit()
        # newMenuItem(r.id)
        response = self.app.post('/restaurant/1/menu/new/', data=dict(name = 'yummy dog2', description= 'you must try this', price= 1, course = 'dessert'))
        print("response: {}".format(response.__dict__))
        print("response[status]: {}".format(response.status_code))
        print("menu item count: {}".format(self.session.query(MenuItem).count()))
        lastItem = self.session.query(MenuItem).order_by(MenuItem.id.desc()).first()
        print("menu item last: {}".format(lastItem.__dict__))
        assert lastItem.name == 'yummy dog2'

    def test_add_restaurant(self):
        u = User(name='john', email='john@example.com', picture="")
        self.session.add(u)
        self.session.commit()
        # newMenuItem(r.id)
        response = self.app.post('/restaurant/new/', data={'name': 'soups r us'})
        print("response: {}".format(response.__dict__))
        print("response[status]: {}".format(response.status_code))
        assert self.session.query(Restaurant).all() != None

class UserViewsTests(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        self.session, self.scoped_session = init_db2('sqlite:///tests.db')
        # app.config['WTF_CSRF_ENABLED'] = False
        # app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(BASE_DIR, 'test.db')
        self.app = app.test_client()
        app.secret_key = 'super_secret_key'
        app.debug = True
        set_db_session(self.session)
        # db.create_all()

    def tearDown(self):
        self.session.close()
        self.scoped_session.remove()
        # Base.metadata.drop_all()


    def test_users_can_login(self):
        u = User(name='joe', email='joe@example.com', picture="12345")
        self.session.add(u)
        self.session.commit()

        # response = self.app.post(url_for('auth.login'), data={'email': 'joe@joes.com', 'picture': '12345'})
        response = self.app.get('/')
        assert response.status_code == 200
        # data = json.loads(response.data)
        # print("data: {}".format(data))
        response = self.app.get('/login')
        assert response.status_code == 200
