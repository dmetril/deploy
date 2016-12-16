from __future__ import unicode_literals
from django.db import models
import re, bcrypt

class UserManager(models.Manager):
	def validator(self, postData, typelogin): 
		EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
		NAME_REGEX = re.compile(r'^[a-zA-Z\-\']{2,}$')
		BDAY_REGEX = re.compile(r'^[0-9]{2}\/[0-9]{2}\/[0-9]{4}$')
		PWORD_REGEX = re.compile(r'(?=^.{8,}$)(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&amp;*()_+}{&quot;:;\'?/&gt;.&lt;,])(?!.*\s).*$')
		errors = [] 
		result = {} 

		if typelogin == 'register': 
			validuser = self.filter(email = postData['email']) 

			if validuser: 
				errors.append('This email has already been registered.')
			if '' in (postData['first_name'], postData['last_name'], postData['email'], postData['birthday'], postData['password'], postData['confirm']): 
				errors.append('Please fill out all fields.')
			if not NAME_REGEX.match(postData['first_name']) or not NAME_REGEX.match(postData['last_name']): 
				errors.append('Please enter a valid name.')
			if not BDAY_REGEX.match(postData['birthday']):
				errors.append('Please enter a valid birthday (dd/mm/yyyy).')
			if not EMAIL_REGEX.match(postData['email']): 
				errors.append('Please enter a valid email address.')
			if not PWORD_REGEX.match(postData['password']): 
				errors.append('Please enter a valid password format (Must be at least 8 characters in length and include one capital letter, one lowercase letter, and one special character).')
			if postData['password'] != postData['confirm']: 
				errors.append('Password and confirmation do not match.')

		elif typelogin == 'login': 
			try: 
				loginuser = self.get(email = postData['email'])
			except User.DoesNotExist:
				loginuser = None

			if not EMAIL_REGEX.match(postData['email']): 
				errors.append('Please enter a valid email address.')
			elif not loginuser: 
				errors.append('Email or password incorrect.')
			elif not bcrypt.hashpw(postData['password'].encode(), loginuser.password.encode()) == loginuser.password.encode(): 
				errors.append('Email or password incorrect.')

		if not errors: 
			if typelogin == 'register': 
				new_user = self.createUser(postData) 
			elif typelogin == 'login': 
				new_user = self.get(email = postData['email']) 
			result['loggedin'] = True 
			result['new_user'] = new_user 

		else: 
			result['loggedin'] = False 
			result['errors'] = errors 

		return result

	def createUser(self, data): 
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


