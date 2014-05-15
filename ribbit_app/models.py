from django.db import models
from django.contrib.auth.models import User
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5 
from Crypto.Hash import SHA256 
from base64 import b64decode, b64encode
import hashlib
import bcrypt

def encrypt(plain_text, key):
    rsakey = RSA.importKey(key)
    rsakey = PKCS1_OAEP.new(rsakey)
    encrypted_text = rsakey.encrypt(plain_text.encode('utf-8'))
    return encrypted_text.encode('base64')

def decrypt(encrypted_text, key):
    rsakey = RSA.importKey(key) 
    rsakey = PKCS1_OAEP.new(rsakey) 
    plain_text = rsakey.decrypt(b64decode(encrypted_text)) 
    return plain_text

def add_signature(private_key, data):
    rsakey = RSA.importKey(private_key) 
    signature = PKCS1_v1_5.new(rsakey) 
    sha256 = SHA256.new() 
    # Data is already base64 encoded (as encrypted with the method 'encrypt')
    sha256.update(b64decode(data)) 
    signed_data = signature.sign(sha256) 
    return b64encode(signed_data)

def verify_signature(public_key, signature, data):
    rsakey = RSA.importKey(public_key) 
    pk_signature = PKCS1_v1_5.new(rsakey) 
    sha256 = SHA256.new() 
    # Data is already base64 encoded (as encrypted with the method 'encrypt')
    sha256.update(b64decode(data)) 

    if pk_signature.verify(sha256, b64decode(signature)):
        return True
    return False

class Ribbit(models.Model):
	content = models.CharField(max_length=140) # This should be stored hashed
	user = models.ForeignKey(User)
	creation_date = models.DateTimeField(auto_now=True, blank=True)
	d_sign = models.CharField(max_length=128, default="")
	retweeted = models.IntegerField(default=0)

class RibbitForFollowers(models.Model):
	public_key = models.CharField(max_length=140)
	encrypted_content = models.ForeignKey(User)
	d_sign = models.CharField(max_length=128, default="")

class UserRibbitEncryption(models.Model):
	user = models.OneToOneField(User)
	public_key = models.CharField(max_length = 1024)

class UserProfile(models.Model):
	user = models.OneToOneField(User)
	private_key = models.CharField(max_length = 1024)
	
	def __unicode__(self):
		return u'%s' % (self.user)
	def gravatar_url(self):
		return "http://www.gravatar.com/avatar/%s?s=50" % hashlib.md5(self.user.email).hexdigest()

class Follow(models.Model):
    follower = models.ForeignKey(User, related_name='follower')
    followed = models.ForeignKey(User, related_name='followed')

    def __unicode__(self):
    	return self.follower.username + " -> " + self.followed.username

class FollowRequest(models.Model):
    follower = models.ForeignKey(User, related_name='rfollower')
    followed = models.ForeignKey(User, related_name='rfollowed')
    requested = models.BooleanField(default=False)
    answered = models.BooleanField(default=False)
    question = models.CharField(max_length=1024,blank=True,null=True)
    answer = models.CharField(max_length=1024,blank=True,null=True)

    def __unicode__(self):
    	return self.follower.username + " -> " + self.followed.username

class Messages(models.Model):
	sender = models.ForeignKey(User, related_name='sender')
	receiver = models.ForeignKey(User, related_name='receiver')
	content = models.CharField(max_length=2048)
	creation_date = models.DateTimeField(auto_now=True, blank=True)
	d_sign = models.CharField(max_length=128, default="")

	def __unicode__(self):
		return u'%s %s %s' % (self.sender,":",self.content)

	def digital_sign(self):
		rec_enc = UserRibbitEncryption.objects.get(user = self.receiver)
		self.d_sign = add_signature(self.sender.profile.private_key, encrypt(self.content, rec_enc.public_key))
		self.save()

	def digital_verify(self):
		sender_enc = UserRibbitEncryption.objects.get(user = self.sender)
		rec_enc = UserRibbitEncryption.objects.get(user = self.receiver)
		ver = verify_signature(sender_enc.public_key, self.d_sign, encrypt(self.content, rec_enc.public_key))
		print self.content
		print ver
		print '*****************************'
		# user_enc = UserRibbitEncryption.objects.get(user = self.sender)
		# print(user_enc.public_key)
		# hashed = decrypt(self.d_sign, user_enc.public_key)
		# match = (hashed == bcrypt.hashpw(self.content.encode('utf-8'), hashed))
		# print(match)
		# print('**************************************')
		# return match

User.profile = property(lambda u: UserProfile.objects.get_or_create(user=u)[0])
User.enc = property(lambda u: UserRibbitEncryption.objects.get_or_create(user=u)[0])

