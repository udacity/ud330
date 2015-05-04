import os
import sys
from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from flask import Flask
from flask.ext.sqlalchemy import SQLAlchemy
# from finalproject import UPLOADS_FOLDER
UPLOAD_FOLDER = "/static/images"
 
Base = declarative_base()

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///restaurantmenuwithusers.db'
db = SQLAlchemy(app)

class User(db.Model):
    __tablename__ = 'user'
   
    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)
    picture = Column(String(250))

    @staticmethod
    def make_unique_nickname(nickname, session):
        if session.query(User).filter_by(name=nickname).first() is None:
            return nickname
        version = 2
        while True:
            new_nickname = nickname + str(version)
            if session.query(User).filter_by(name=new_nickname).first() is None:
                break
            version += 1
        return new_nickname

    @staticmethod
    def create(login_session, session):
        newUser = User(name = login_session['username'], email = login_session['email'], picture = login_session['picture'])
        session.add(newUser)
        session.commit()
        user = session.query(User).filter_by(email = login_session['email']).first()
        return user.id

    @staticmethod
    def find_id_by_email(email, session):
        try:
            user = session.query(User).filter_by(email = email).first()
            return user.id
        except:
            return None

    def __init__(self, name, email, picture):
        self.name = name
        self.email = email
        self.picture = picture

    def __repr__(self):
        return '<User %r>' % self.name



class Restaurant(db.Model):
    __tablename__ = 'restaurant'
   
    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
       """Return object data in easily serializeable format"""
       return {
           'name'         : self.name,
           'id'           : self.id,
           'user_id'   : self.user_id
       }
 
    def __init__(self, name, user_id):
        self.name = name
        self.user_id = user_id

    def __repr__(self):
        return '<Restaurant %r>' % self.name

class MenuItem(db.Model):
    __tablename__ = 'menu_item'


    name =Column(String(80), nullable = False)
    id = Column(Integer, primary_key = True)
    description = Column(String(250))
    price = Column(String(8))
    course = Column(String(250))
    restaurant_id = Column(Integer,ForeignKey('restaurant.id'))
    restaurant = relationship(Restaurant)
    imagefile = Column(String(250))
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
       """Return object data in easily serializeable format"""
       return {
           'name'         : self.name,
           'description'         : self.description,
           'id'         : self.id,
           'price'         : self.price,
           'course'         : self.course,
       }

    def imageURL(self):
      return UPLOAD_FOLDER + "/" + self.imagefile

    def __init__(self, name, description, price, course, restaurant, imagefile, user_id):
        self.name = name
        self.description = description
        self.price = price
        self.course = course
        self.restaurant = restaurant
        self.imagefile = imagefile
        self.user_id = user_id

    # def __init__(self, name, description, price, course, restaurant_id, imagefile, user_id):
    #     self.name = name
    #     self.description = description
    #     self.price = price
    #     self.course = course
    #     self.restaurant_id = restaurant_id
    #     self.imagefile = imagefile
    #     self.user_id = user_id

    def __repr__(self):
        return '<MenuItem %r>' % self.name
        

db.create_all()
db.session.commit()
User1 = User(name="Tinny Tim", email="tinnyTim@udacity.com", picture='https://pbs.twimg.com/profile_images/2671170543/18debd694829ed78203a5a36dd364160_400x400.png')
db.session.add(User1)
db.session.commit()
print("created tables")

