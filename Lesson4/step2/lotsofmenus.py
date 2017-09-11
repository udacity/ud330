#! /usr/bin/env python3

import locale
import random
from faker import Faker
from sqlalchemy.orm import sessionmaker
from database_setup import Restaurant, Base, MenuItem, User, engine

# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()
session = DBSession()
locale.setlocale(locale.LC_ALL, 'en_US.UTF-8')
fake = Faker()

for i in range(0, 10):
    user = User(
        name=fake.name(),
        email=fake.email(),
        picture='https://pbs.twimg.com/profile_images/2671170543/'
                '18debd694829ed78203a5a36dd364160_400x400.png'
    )
    session.add(user)
session.commit()

for i in range(0, 10):
    restaurant = Restaurant(
        user_id=i + 1,
        name=fake.text()
    )
    session.add(restaurant)
session.commit()

course_elements = ["Entree", "Dessert", "Beverage", "Appetizer"]

for i in range(0, 1000):
    restaurant = session.query(Restaurant).filter_by(
        id=random.randint(1, 10)
    ).first()

    menuItem = MenuItem(
        user_id=restaurant.user_id,
        name=fake.lexify("???????? ??????"),
        description=fake.text(),
        price=locale.currency(round(random.randint(100, 10000) / 100, 2)),
        course=fake.random_element(course_elements),
        restaurant=restaurant
    )
    session.add(menuItem)

session.commit()

print("added all the items items!")
