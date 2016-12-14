from __future__ import unicode_literals
from django.db import models
import re, bcrypt

class UserManager(models.Manager):
	def validator(self, postData, typelogin): #method to validate login/register entries
		EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
		NAME_REGEX = re.compile(r'^[a-zA-Z\-\']{2,}$')
		BDAY_REGEX = re.compile(r'^[0-9]{2}\/[0-9]{2}\/[0-9]{4}$')
		PWORD_REGEX = re.compile(r'(?=^.{8,}$)(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&amp;*()_+}{&quot;:;\'?/&gt;.&lt;,])(?!.*\s).*$')
		errors = [] #empty list to push errors to
		result = {} #empty dictionary to store return values

		if typelogin == 'register': #if a user tries to register!
			validuser = self.filter(email = postData['email']) #retrieve user info based on the entered e-mail...if it exists...

			if validuser: #if the email is already in the database...
				errors.append('This email has already been registered.')
			if '' in (postData['first_name'], postData['last_name'], postData['email'], postData['birthday'], postData['password'], postData['confirm']): #if any of the fields are left blank...
				errors.append('Please fill out all fields.')
			if not NAME_REGEX.match(postData['first_name']) or not NAME_REGEX.match(postData['last_name']): #if either first_name or last_name are in the wrong format...
				errors.append('Please enter a valid name.')
			if not BDAY_REGEX.match(postData['birthday']): #if the birthday is entered in the wrong format...
				errors.append('Please enter a valid birthday (dd/mm/yyyy).')
			if not EMAIL_REGEX.match(postData['email']): #if the email is entered in the wrong format...
				errors.append('Please enter a valid email address.')
			if not PWORD_REGEX.match(postData['password']): #if the password doesn't meet the requirements...
				errors.append('Please enter a valid password format (Must be at least 8 characters in length and include one capital letter, one lowercase letter, and one special character).')
			if postData['password'] != postData['confirm']: #if the password and confirm password don't match...
				errors.append('Password and confirmation do not match.')

		elif typelogin == 'login': #if a user tries to log in...
			try: #attempt to retrieve the user's information based on the provided e-mail
				loginuser = self.get(email = postData['email'])
			except User.DoesNotExist: #if the entered e-mail doesn't match anything in the database...
				loginuser = None

			if not EMAIL_REGEX.match(postData['email']): #if the email addy entered isn't a valid format...
				errors.append('Please enter a valid email address.')
			elif not loginuser: #if the email entered does not match anything in the database...
				errors.append('Email or password incorrect.')
			elif not bcrypt.hashpw(postData['password'].encode(), loginuser.password.encode()) == loginuser.password.encode(): #if the password is incorrect...
				errors.append('Email or password incorrect.')

		if not errors: #if there are no errors...
			if typelogin == 'register': #if the user tried to register...
				new_user = self.createUser(postData) #set new_user based on the information the user entered to register
			elif typelogin == 'login': #if the user was loggin in...
				new_user = self.get(email = postData['email']) #set new_user to the values based on the log in information
			result['loggedin'] = True #set logged in to true
			result['new_user'] = new_user #pass the new_user information to the returned result

		else: #if there are errors...
			result['loggedin'] = False #set logged in to false
			result['errors'] = errors #pass the errors in the returned result

		return result

	def createUser(self, data): #method to enter the user information into the database
		new_user = self.create(first_name = data['first_name'], last_name = data['last_name'], birthday = data['birthday'], email = data['email'], password = bcrypt.hashpw(data['password'].encode(), bcrypt.gensalt()))
		return new_user

class User(models.Model): #user database
	first_name = models.CharField(max_length = 255)
	last_name = models.CharField(max_length = 255)
	email = models.CharField(max_length = 255)
	password = models.CharField(max_length = 255)
	birthday = models.CharField(max_length = 255)
	created_at = models.DateTimeField(auto_now_add = True)
	updated_at = models.DateTimeField(auto_now = True)
	objects = UserManager()

# Create your models here.
