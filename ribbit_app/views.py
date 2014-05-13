from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.decorators import login_required
from django.db.models import Count
from django.contrib.auth.models import User
from django.http import Http404
from django.core.exceptions import ObjectDoesNotExist
from ribbit_app.forms import AuthenticateForm, UserCreateForm, RibbitForm
from ribbit_app.models import *
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5 
from Crypto.Hash import SHA256 
from base64 import b64decode, b64encode

#don't forget to fix the commeted line
def index(request, auth_form=None, user_form=None):
	# User is logged in
	if request.user.is_authenticated():
		ribbit_form = RibbitForm()
		user = request.user
		ribbits_self = []
		for qribbit in Ribbit.objects.filter(user=user.id):
			ribbits_self.append(qribbit)
		ribbits_buddies = []
		for fuser in Follow.objects.filter(follower=request.user):
			for ribbit in Ribbit.objects.filter(user=fuser.followed):
				print ribbit.content
				ribbits_buddies.append(ribbit)
		# ribbits_buddies = Ribbit.objects.filter(user__userprofile__in=user.profile.follows.all)
		print ribbits_buddies
		ribbits = ribbits_self + ribbits_buddies
		ribbits.sort(key=lambda x: x.creation_date, reverse=False)
		return render(request,
					  'buddies.html',
					  {'ribbit_form': ribbit_form, 'user': user,
					   'ribbits': ribbits,
					   'next_url': '/', })
	else:
		# User is not logged in
		auth_form = auth_form or AuthenticateForm()
		user_form = user_form or UserCreateForm()

		return render(request,
					  'home.html',
					  {'auth_form': auth_form, 'user_form': user_form, })


def login_view(request):
	if request.method == 'POST':
		form = AuthenticateForm(data=request.POST)
		if form.is_valid():
			login(request, form.get_user())
			# Success
			return redirect('/')
		else:
			# Failure
			return index(request, auth_form=form)
	return redirect('/')


def logout_view(request):
	logout(request)
	return redirect('/')

def signup(request):
	user_form = UserCreateForm(data=request.POST)
	if request.method == 'POST':
		if user_form.is_valid():
			username = user_form.clean_username()
			password = user_form.clean_password2()
			user_form.save()
			user = authenticate(username=username, password=password)
			keys = create_keys(bits=1024)
			user_profile = user.profile
			user_profile.private_key = get_private_key(keys)
			public_key_object = user.enc
			public_key_object.public_key = get_public_key(keys)
			public_key_object.save()
			user_profile.save()
			login(request, user)
			return redirect('/')
		else:
			return index(request, user_form=user_form)
	return redirect('/')


@login_required
def public(request, ribbit_form=None):
	ribbit_form = ribbit_form or RibbitForm()
	ribbits = Ribbit.objects.reverse()[:10]
	return render(request,
				  'public.html',
				  {'ribbit_form': ribbit_form, 'next_url': '/ribbits',
				   'ribbits': ribbits, 'username': request.user.username})


@login_required
def submit(request):
	if request.method == "POST":
		ribbit_form = RibbitForm(data=request.POST)
		next_url = request.POST.get("next_url", "/")
		if ribbit_form.is_valid(): 
			ribbit = ribbit_form.save(commit=False)
			ribbit.user = request.user
			user_profile = UserProfile.objects.get(user=request.user)
			ribbit.content = encrypt(ribbit.content,user_profile.private_key)
			ribbit.save()
			return redirect(next_url)
		else:
			return public(request, ribbit_form)
	return redirect('/')


def get_latest(user):
	try:
		return user.ribbit_set.order_by('id').reverse()[0]
	except IndexError:
		return ""


@login_required
def users(request, username="", ribbit_form=None):
	if username:
		# Show a profile
		try:
			user = User.objects.get(username=username)
		except User.DoesNotExist:
			raise Http404
		ribbits = Ribbit.objects.filter(user=user.id)
		# username2=''
		# try:
		# 	username2=Follow.objects.filter(follower=request.user,followed=User.objects.get(username=username))
		# 	print 'tryyyy'
		# except:
		# 	username2=''
		if username == request.user.username or Follow.objects.filter(follower=request.user,followed=User.objects.get(username=username)):#username2:# or Follow.objects.get(follower=request.user,followed=User.objects.get(username=username)).followed.username:
		#or request.user.profile.follows.filter(user__username=username):
			# Self Profile
			return render(request, 'user.html', {'user': user, 'ribbits': ribbits, })
		return render(request, 'user.html', {'user': user, 'ribbits': ribbits, 'follow': True, })
	users = User.objects.all().annotate(ribbit_count=Count('ribbit'))
	ribbits = map(get_latest, users)
	obj = zip(users, ribbits)
	ribbit_form = ribbit_form or RibbitForm()
	return render(request,
				  'profiles.html',
				  {'obj': obj, 'next_url': '/users/',
				   'ribbit_form': ribbit_form,
				   'username': request.user.username, })

@login_required
def messages(request):
	try:
		senders = [message.sender for message in Messages.objects.filter(receiver=request.user.id)]
		output_dict = {'senders': list(set(senders))}
		return render(request,'messages.html', output_dict)
	except User.DoesNotExist:
			raise Http404

@login_required
def view_messages(request,username):
	#print User.objects.get(id=request.user.id).profile.follows.objects.get(id=request.user.id)
	#print UserProfile.objects.get(user=request.user).follows.all()
	try:
		if request.user.id == User.objects.get(username=username).id:
			raise Http404
		sender_messages = [message for message in Messages.objects.filter(receiver=request.user.id, sender=User.objects.get(username=username).id)]
		reciever_messages = [message for message in Messages.objects.filter(receiver=User.objects.get(username=username).id, sender=request.user.id)]
		messages = sender_messages+reciever_messages
		messages.sort(key=lambda x: x.creation_date, reverse=False)
		output_dict = {'messages': messages,
						'next_url': u'/messages/%s/send_message' % (username)}
		return render(request,'view_messages.html', output_dict)
	except User.DoesNotExist:
            raise Http404

#what's missing that i shouldn't be able to send messages only to those i follow and follow me
@login_required
def send_message(request,username):
	if 'sent_message' in request.POST and request.POST['sent_message']:
		message = Messages.objects.create(sender=request.user, receiver=User.objects.get(username=username), content=request.POST['sent_message'])
		message.digital_sign()
		print 'haloloealaaa'
		return redirect(u'/messages/%s' % (username))
	else:
		raise Http404

@login_required
def follow(request):
	if request.method == "POST":
		follow_id = request.POST.get('follow', False)
		if follow_id:
			try:
				user = User.objects.get(id=follow_id)
				Follow.objects.create(follower=request.user,followed=user)
			except ObjectDoesNotExist:
				return redirect('/users/')
	return redirect('/users/')

@login_required
def unfollow(request):
	if request.method == "POST":
		unfollow_id = request.POST.get('unfollow', False)
		if unfollow_id:
			try:
				user = User.objects.get(id=unfollow_id)
				Follow.objects.get(follower=request.user,followed=user).delete()
			except ObjectDoesNotExist:
				return redirect('/users/')
	return redirect('/users/')

def create_keys(bits):
    keys = RSA.generate(bits)
    return keys

def get_private_key(keys):
    private_key = keys.exportKey()
    return private_key

def get_public_key(keys):
    public_key = keys.publickey().exportKey()
    return public_key

@login_required
def encrypt(plain_text, key):
    rsakey = RSA.importKey(key)
    rsakey = PKCS1_OAEP.new(rsakey)
    encrypted_text = rsakey.encrypt(plain_text)
    return encrypted_text.encode('base64')

@login_required
def decrypt(encrypted_text, key):
    rsakey = RSA.importKey(key) 
    rsakey = PKCS1_OAEP.new(rsakey) 
    plain_text = rsakey.decrypt(b64decode(encrypted_text)) 
    return plain_text

@login_required
def add_signature(private_key, data):
    rsakey = RSA.importKey(private_key) 
    signature = PKCS1_v1_5.new(rsakey) 
    sha256 = SHA256.new() 
    # Data is already base64 encoded (as encrypted with the method 'encrypt')
    sha256.update(b64decode(data)) 
    signed_data = signature.sign(sha256) 
    return b64encode(signed_data)

@login_required
def verify_signature(public_key, signature, data):
    rsakey = RSA.importKey(public_key) 
    signature = PKCS1_v1_5.new(rsakey) 
    sha256 = SHA256.new() 
    # Data is already base64 encoded (as encrypted with the method 'encrypt')
    sha256.update(b64decode(data)) 
    if signature.verify(sha256, b64decode(signature)):
        return True
    return False

