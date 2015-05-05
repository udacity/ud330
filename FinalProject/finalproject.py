from flask import Flask, render_template, request, redirect,jsonify, url_for, flash, g, abort
app = Flask(__name__)

from flask_wtf.csrf import CsrfProtect
from flask_wtf import Form
from flask_wtf.file import FileField, FileAllowed, FileRequired
from flask.ext.sqlalchemy import SQLAlchemy
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import scoped_session, sessionmaker
from werkzeug import secure_filename

from flask import session as login_session
import random, string 

#IMPORTS FOR THIS STEP
#from oauth2client.client import AccessTokenRefreshError
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json 
from flask import make_response
import requests
import os
from database_setup import Base, Restaurant, MenuItem, User


ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'])

UPLOADS_FOLDER = "/static/images"
UPLOADS_DEFAULT_DEST = "static/images"

app.config['UPLOAD_FOLDER'] = UPLOADS_FOLDER
csrf = CsrfProtect()

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS

def set_db_session(session):
  app.db_session = session

def set_login_session_user_id(userid):
  app.secret_key = 'super_secret_key'
  login_session['user_id'] = userid
  print ("In set_login_session_user_id: {}".format(login_session))


def init(db_filename):
  """Initializes the database."""
  app = Flask(__name__)
  app.config['SQLALCHEMY_DATABASE_URI'] = db_filename
  app.config['SESSION_TYPE'] = 'filesystem'
  db = SQLAlchemy(app)
  db.create_all()
  return db


# Create a state token to prevent request forgery.
# Store it in the session for later validation.
@app.route('/login')
def showLogin():
    print ("In login")
    state = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in range(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)

@app.route('/gconnect', methods=['POST'])
def gconnect():
  
  #print 'received state of %s' %request.args.get('state')
  #print 'login_sesion["state"] = %s' %login_session['state']
  if request.args.get('state') != login_session['state']:
    response = make_response(json.dumps('Invalid state parameter.'), 401)
    response.headers['Content-Type'] = 'application/json'
    return response
  
  #gplus_id = request.args.get('gplus_id')
  #print "request.args.get('gplus_id') = %s" %request.args.get('gplus_id')
  request.get_data()
  code = request.data.decode('utf-8')
  print ("received code of %s " % code)

  try:
    # Upgrade the authorization code into a credentials object
    oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
    oauth_flow.redirect_uri = 'postmessage'
    credentials = oauth_flow.step2_exchange(code)
  except FlowExchangeError:
    response = make_response(json.dumps('Failed to upgrade the authorization code.'), 401)
    response.headers['Content-Type'] = 'application/json'
    return response

  # Check that the access token is valid.
  access_token = credentials.access_token
  url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
         % access_token)
  h = httplib2.Http()
  response = h.request(url, 'GET')[1]
  str_response = response.decode('utf-8')
  result = json.loads(str_response)
  # If there was an error in the access token info, abort.
  if result.get('error') is not None:
    response = make_response(json.dumps(result.get('error')), 500)
    response.headers['Content-Type'] = 'application/json'

    
  # Verify that the access token is used for the intended user.
  gplus_id = credentials.id_token['sub']
  if result['user_id'] != gplus_id:
    response = make_response(
        json.dumps("Token's user ID doesn't match given user ID."), 401)
    response.headers['Content-Type'] = 'application/json'
    return response
  # Verify that the access token is valid for this app.


  if result['issued_to'] != CLIENT_ID:
    response = make_response(
        json.dumps("Token's client ID does not match app's."), 401)
    print ("Token's client ID does not match app's.")
    response.headers['Content-Type'] = 'application/json'
    return response

  
  stored_credentials = login_session.get('credentials_access_token')
  stored_gplus_id = login_session.get('gplus_id')
  if stored_credentials is not None and gplus_id == stored_gplus_id:
    response = make_response(json.dumps('Current user is already connected.'),
                             200)
    response.headers['Content-Type'] = 'application/json'
    
  # Store the access token in the session for later use.
  login_session['provider'] = 'google'
  login_session['credentials_access_token'] = access_token
  login_session['gplus_id'] = gplus_id
  response = make_response(json.dumps('Successfully connected user.', 200))
  
  #Get user info
  userinfo_url =  "https://www.googleapis.com/oauth2/v1/userinfo"
  params = {'access_token': access_token, 'alt':'json'}
  answer = requests.get(userinfo_url, params=params)
  data = json.loads(answer.text)
  
  
  login_session['username'] = data["name"]
  login_session['picture'] = data["picture"]
  login_session['email'] = data["email"]
  #print login_session['email']

  # see if user exists, if it doesn't make a new one
  user_id = getUserID(data["email"], app.db_session)
  if not user_id:
    user_id = createUser(login_session, app.db_session)
  login_session['user_id'] = user_id


  output = ''
  output +='<h1>Welcome, '
  output += login_session['username']

  output += '!</h1>'
  output += '<img src="'
  output += login_session['picture']
  output +=' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
  flash("you are now logged in as %s"%login_session['username'])
  return output

#Revoke current user's token and reset their login_session.
@app.route("/gdisconnect")
def gdisconnect():
  

  # Only disconnect a connected user.
  access_token = login_session.get('credentials_access_token')
  if access_token is None:
    response = make_response(json.dumps('Current user not connected.'), 401)
    response.headers['Content-Type'] = 'application/json'
    return response

  # Execute HTTP GET request to revoke current token.
  url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
  h = httplib2.Http()
  result = h.request(url, 'GET')[0]

  if result['status'] == '200':
    # Reset the user's session.
    
    

    response = make_response(json.dumps('Successfully disconnected.'), 200)
    response.headers['Content-Type'] = 'application/json'
    return response
  else:
    # For whatever reason, the given token was invalid.
    response = make_response(
        json.dumps('Failed to revoke token for given user.', 400))
    response.headers['Content-Type'] = 'application/json'
    return response


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
  if request.args.get('state') != login_session['state']:
    response = make_response(json.dumps('Invalid state parameter.'), 401)
    response.headers['Content-Type'] = 'application/json'
    return response
  request.get_data()
  access_token = request.data.decode('utf-8')
  print ("access token received %s "% access_token)

  #Exchange client token for long-lived server-side token
 ## GET /oauth/access_token?grant_type=fb_exchange_token&client_id={app-id}&client_secret={app-secret}&fb_exchange_token={short-lived-token} 
  app_id = json.loads(open('fb_client_secrets.json', 'r').read())['web']['app_id']
  app_secret = json.loads(open('fb_client_secrets.json', 'r').read())['web']['app_secret']
  url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (app_id,app_secret,access_token)
  h = httplib2.Http()
  response = h.request(url, 'GET')[1]
  str_response = response.decode('utf-8')

  #Use token to get user info from API 
  #strip expire tag from access token
  token = str_response.split("&")[0]
  
  url = 'https://graph.facebook.com/v2.2/me?%s' % token
  h = httplib2.Http()
  response = h.request(url, 'GET')[1]
  str_response = response.decode('utf-8')
  data = json.loads(str_response)

  login_session['provider'] = 'facebook'
  login_session['username'] = data["name"]
  login_session['email'] = data["email"]
  login_session['facebook_id'] = data["id"]
  

  #Get user picture
  url = 'https://graph.facebook.com/v2.2/me/picture?%s&redirect=0&height=200&width=200' % token
  h = httplib2.Http()
  response = h.request(url, 'GET')[1]
  str_response = response.decode('utf-8')
  data = json.loads(str_response)
  login_session['picture'] = data["data"]["url"]
  
  # see if user exists
  user_id = getUserID(login_session['email'], app.db_session)
  if not user_id:
    user_id = createUser(login_session, app.db_session)
  login_session['user_id'] = user_id
    
  output = ''
  output +='<h1>Welcome, '
  output += login_session['username']

  output += '!</h1>'
  output += '<img src="'
  output += login_session['picture']
  output +=' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '


  flash ("Now logged in as %s" % login_session['username'])
  return output

@app.route('/fbdisconnect')
def fbdisconnect():
  facebook_id = login_session['facebook_id']
  url = 'https://graph.facebook.com/%s/permissions' % facebook_id
  h = httplib2.Http()
  result = h.request(url, 'DELETE')[1] 
  return "you have been logged out"

#####

@app.route('/restaurant/<int:restaurant_id>/menu/JSON')
def restaurantMenuJSON(restaurant_id):
    restaurant = app.db_session.query(Restaurant).filter_by(id = restaurant_id).one()
    items = app.db_session.query(MenuItem).filter_by(restaurant_id = restaurant_id).all()
    return jsonify(MenuItems=[i.serialize for i in items])


@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/JSON')
def menuItemJSON(restaurant_id, menu_id):
    Menu_Item = app.db_session.query(MenuItem).filter_by(id = menu_id).one()
    return jsonify(Menu_Item = Menu_Item.serialize)

@app.route('/restaurant/JSON')
def restaurantsJSON():
    restaurants = app.db_session.query(Restaurant).all()
    return jsonify(restaurants= [r.serialize for r in restaurants])

@app.route('/disconnect')
def disconnect():
  if 'provider' in login_session:
    if login_session['provider'] == 'google':
      gdisconnect()
      del login_session['gplus_id']
      del login_session['credentials_access_token']
    if login_session['provider'] == 'facebook':
      fbdisconnect()
      del login_session['facebook_id']

    del login_session['username']
    del login_session['email']
    del login_session['picture']
    del login_session['user_id']
    del login_session['provider']
    flash("You have successfully been logged out.")
    return redirect(url_for('showRestaurants'))
  else:
    flash("You were not logged in")
    redirect(url_for('showRestaurants'))

#Show all restaurants
@app.route('/')
@app.route('/restaurant/')
def showRestaurants():
  print("In restaurant")
  restaurants = app.db_session.query(Restaurant).order_by(asc(Restaurant.name))
  print("Restaurants count: {}".format(restaurants.count()))
  print("first Restaurants : {}".format(restaurants.first()))
  if 'username' not in login_session:
    return render_template('publicrestaurants.html', restaurants=restaurants)
  else:
    return render_template('restaurants.html', restaurants = restaurants)

#Create a new restaurant
@app.route('/restaurant/new/', methods=['GET','POST'])
def newRestaurant():
  print("In newRestaurant, login_session: {}".format(login_session))
  if 'user_id' not in login_session:
    return redirect('/login')
  if request.method == 'POST':
      newRestaurant = Restaurant(name = request.form['name'], user_id=login_session['user_id'])
      app.db_session.add(newRestaurant)
      flash('New Restaurant %s Successfully Created' % newRestaurant.name)
      app.db_session.commit()
      return redirect(url_for('showRestaurants'))
  else:
      return render_template('newRestaurant.html')

    #return "This page will be for making a new restaurant"

#Edit a restaurant
@app.route('/restaurant/<int:restaurant_id>/edit/', methods = ['GET', 'POST'])
def editRestaurant(restaurant_id):
  editedRestaurant = app.db_session.query(Restaurant).filter_by(id = restaurant_id).one()
  if 'user_id' not in login_session:
    return redirect('/login')
  if editedRestaurant.user_id != login_session['user_id']:
    return "<script>function myFunction() {alert('You are not authorized to edit this restaurant. Please create your own restaurant in order to edit.');}</script><body onload='myFunction()''>"
  if request.method == 'POST':
      if request.form['name']:
        editedRestaurant.name = request.form['name']
        flash('Restaurant Successfully Edited %s' % editedRestaurant.name)
        return redirect(url_for('showRestaurants'))
  else:
    return render_template('editRestaurant.html', restaurant = editedRestaurant)


#Delete a restaurant
@app.route('/restaurant/<int:restaurant_id>/delete/', methods = ['GET','POST'])
def deleteRestaurant(restaurant_id):
  restaurantToDelete = app.db_session.query(Restaurant).filter_by(id = restaurant_id).one()
  if 'user_id' not in login_session:
    return redirect('/login')
  if restaurantToDelete.user_id != login_session['user_id']:
    return "<script>function myFunction() {alert('You are not authorized to delete this restaurant. Please create your own restaurant in order to delete.');}</script><body onload='myFunction()''>"
  if request.method == 'POST':
    app.db_session.delete(restaurantToDelete)
    flash('%s Successfully Deleted' % restaurantToDelete.name)
    app.db_session.commit()
    return redirect(url_for('showRestaurants', restaurant_id = restaurant_id))
  else:
    return render_template('deleteRestaurant.html',restaurant = restaurantToDelete)

#Show a restaurant menu
@app.route('/restaurant/<int:restaurant_id>/')
@app.route('/restaurant/<int:restaurant_id>/menu/')
def showMenu(restaurant_id):
    restaurant = app.db_session.query(Restaurant).filter_by(id = restaurant_id).one()


    creator = getUserInfo(restaurant.user_id, app.db_session)
    print("creator: {} {}".format(creator.name, creator.id))
    print("login_session id: {}".format(login_session.get('user_id')))
    print("login_session name: {}".format(login_session.get('username')))

    items = app.db_session.query(MenuItem).filter_by(restaurant_id = restaurant_id).all()
    if 'username' not in login_session or creator.id != login_session['user_id']:
      return render_template('publicmenu.html', items = items, restaurant = restaurant, creator= creator)
    else:
      return render_template('menu.html', items = items, restaurant = restaurant,creator = creator)
     


#Create a new menu item
@app.route('/restaurant/<int:restaurant_id>/menu/new/',methods=['GET','POST'])
def newMenuItem(restaurant_id):
  print("In newMenuItem, login_session: {}".format(login_session))
  if 'user_id' not in login_session:
    return redirect('/login')
  print("NewMenuItem:: UserID is good")
  restaurant = app.db_session.query(Restaurant).filter_by(id = restaurant_id).one()
  if login_session['user_id'] != restaurant.user_id:
    return "<script>function myFunction() {alert('You are not authorized to add menu items to this restaurant. Please create your own restaurant in order to add items.');}</script><body onload='myFunction()''>"
  print("NewMenuItem:: Authorized to add menu items")
  print("request method: {}".format(request.method))
  if request.method == 'POST':
      request.get_data()
      files = request.files
      file = request.files['fileToUpload']
      if file and allowed_file(file.filename):
          filename = secure_filename(file.filename)
          file.save(os.path.join(UPLOADS_DEFAULT_DEST, filename))
          newItem = MenuItem(name = request.form['name'], description = request.form['description'], price = request.form['price'], course = request.form['course'], restaurant = restaurant, user_id=restaurant.user_id, imagefile = filename)
          app.db_session.add(newItem)
          app.db_session.commit()
          flash('New Menu %s Item Successfully Created' % (newItem.name))
          print("menuitem url: {0}".format(url_for('showMenu', restaurant_id=restaurant.id)))
          return redirect(url_for('showMenu', restaurant_id=restaurant.id))
  else:
      return render_template('newmenuitem.html', restaurant_id = restaurant_id)


#Edit a menu item
@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/edit', methods=['GET','POST'])
def editMenuItem(restaurant_id, menu_id):
    if 'user_id' not in login_session:
      return redirect('/login')

    editedItem = app.db_session.query(MenuItem).filter_by(id = menu_id).one()
    restaurant = app.db_session.query(Restaurant).filter_by(id = restaurant_id).one()

    if login_session['user_id'] != restaurant.user_id:
      return "<script>function myFunction() {alert('You are not authorized to edit menu items to this restaurant. Please create your own restaurant in order to edit items.');}</script><body onload='myFunction()''>"
    if request.method == 'POST':
      request.get_data()
      files = request.files
      file = request.files['fileToUpload']
      if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(UPLOADS_DEFAULT_DEST, filename))
        editedItem.imagefile = filename
        
      if request.form['name']:
          editedItem.name = request.form['name']
      if request.form['description']:
          editedItem.description = request.form['description']
      if request.form['price']:
          editedItem.price = request.form['price']
      if request.form['course']:
          editedItem.course = request.form['course']
      app.db_session.add(editedItem)
      app.db_session.commit() 
      flash('Menu Item Successfully Edited')
      return redirect(url_for('showMenu', restaurant_id = restaurant_id))
    else:
        print("item: {}".format(editedItem.__dict__))
        return render_template('editmenuitem.html', restaurant_id = restaurant_id, menu_id = menu_id, item = editedItem)


#Delete a menu item
@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/delete', methods = ['GET','POST'])
def deleteMenuItem(restaurant_id,menu_id):
    if 'user_id' not in login_session:
      return redirect('/login')
    restaurant = app.db_session.query(Restaurant).filter_by(id = restaurant_id).one()
    itemToDelete = app.db_session.query(MenuItem).filter_by(id = menu_id).one() 
    if login_session['user_id'] != restaurant.user_id:
      return "<script>function myFunction() {alert('You are not authorized to delete menu items to this restaurant. Please create your own restaurant in order to delete items.');}</script><body onload='myFunction()''>"
    if request.method == 'POST':
        app.db_session.delete(itemToDelete)
        app.db_session.commit()
        flash('Menu Item Successfully Deleted')
        return redirect(url_for('showMenu', restaurant_id = restaurant_id))
    else:
        return render_template('deleteMenuItem.html', item = itemToDelete)


def getUserID(email, db_session):
    try:
        user = db_session.query(User).filter_by(email = email).one()
        return user.id
    except:
        return None


def getUserInfo(user_id, db_session):
    user = db_session.query(User).filter_by(id = user_id).one()
    return user


def createUser(login_session, db_session):
    newUser = User(name = login_session['username'], email = login_session['email'], picture = login_session['picture'])
    db_session.add(newUser)
    db_session.commit()
    user = db_session.query(User).filter_by(email = login_session['email']).one()
    return user.id

# @app.before_request
# def csrf_protect():
#     if request.method == "POST":
#         token = login_session.pop('_csrf_token', None)
#         print ("in csrf_protect: token {}".format(token))
#         if not token or token != request.form.get('_csrf_token'):
#             abort(403)

# def generate_csrf_token():
#   if '_csrf_token' not in login_session:
#     login_session['_csrf_token'] = some_random_string()
#   print ("in generate_csrf_token: token {}".format(login_session['_csrf_token']))
#   return login_session['_csrf_token']

if __name__ == '__main__':
  app.secret_key = 'super_secret_key'
  WTF_CSRF_ENABLED = True
  app.debug = True
  CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
  APPLICATION_NAME = "Restaurant Menu Application"
  app.db_session = init('sqlite:///restaurantmenuwithusers.db').session
  csrf.init_app(app)
  # app.jinja_env.globals['csrf_token'] = generate_csrf_token    
  # print("csrf_token: {}".format(csrf_token()))    
  app.run(host = '0.0.0.0', port = 5000)
