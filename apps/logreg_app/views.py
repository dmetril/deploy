from django.shortcuts import render, redirect
from django.contrib import messages
from .models import User

def index(request):
	return render(request, 'logreg/index.html')

def process(request, typelogin): #route to process the entered information if a user attempts to log in or register
	result = User.objects.validator(request.POST, typelogin) #get a result based on the user's entered information
	request.session['loggedin'] = result['loggedin'] #store whether or not the user is logged in in session

	if result['loggedin']: #if the user is logged in based on the entered information...
		request.session['user'] = result['new_user'] #store the user's information in session
		return redirect('/success') #redirect the user to the success route
	else: #if the user is not logged in based on the entered information...
		for error in result['errors']: #for every error...
			messages.error(request, error) #make a flash message
		return redirect('/') #redirect back to root

def success(request):
	if not request.session['loggedin']: #if the user is not logged in...
		return redirect('/') #redirect the user back to root
	else: #if they are logged in...
		return render(request, 'logreg/success.html') #render the success page

def logout(request):
	request.session['loggedin'] = False #log the user out
	return redirect('/') #redirect to root

# Create your views here.
