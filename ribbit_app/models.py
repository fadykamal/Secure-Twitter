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
	user = models.ForeignKey(User)
	creation_date = models.DateTimeField(auto_now=True, blank=True)
	retweeted = models.IntegerField(default=0)

	def digital_sign(self):
		self.d_sign = add_signature(self.user.profile.private_key, b64encode(self.content))
		self.save()

	def digital_verify(self):
		user_enc = UserRibbitEncryption.objects.get(user = self.user)
		ver = verify_signature(user_enc.public_key, self.d_sign, b64encode(self.content))
		return ver

class RibbitForFollowers(models.Model):
	ribbit = models.ForeignKey(Ribbit)
	public_key = models.CharField(max_length=140)
	encrypted_content = models.CharField(max_length=140)
	d_sign = models.CharField(max_length=128, default="")
	creation_date = models.DateTimeField(auto_now=True, blank=True)

	def digital_sign(self):
		user = UserRibbitEncryption.objects.get(public_key=self.public_key).user
		self.d_sign = add_signature(user.profile.private_key, b64encode(self.encrypted_content))
		self.save()

	def digital_verify(self):
		user_enc = UserRibbitEncryption.objects.get(user = self.user)
		ver = verify_signature(self.public_key, self.d_sign, b64encode(self.encrypted_content))
		return ver

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
    #requested = models.BooleanField(default=False)
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
	d_sign = models.CharField(max_length=256, default="")

	def __unicode__(self):
		return u'%s %s %s' % (self.sender,":",self.content)

	def digital_sign(self):
		self.d_sign = add_signature(self.sender.profile.private_key, b64encode(self.content))
		self.save()

	def digital_verify(self):
		sender_enc = UserRibbitEncryption.objects.get(user = self.sender)
		rec_enc = UserRibbitEncryption.objects.get(user = self.receiver)
		ver = verify_signature(sender_enc.public_key, self.d_sign, b64encode(self.content))
		return ver

User.profile = property(lambda u: UserProfile.objects.get_or_create(user=u)[0])
User.public_key = property(lambda u: UserRibbitEncryption.objects.get_or_create(user=u)[0].public_key)
RibbitForFollowers.get_rebbit = property(lambda u: (Ribbit.objects.get_or_create(id=u.id)[0]))
RibbitForFollowers.user = property(lambda u: ((UserRibbitEncryption.objects.get_or_create(public_key=u.public_key)[0]).user))
RibbitForFollowers.content = property(lambda u: (decrypt(u.encrypted_content, u.user.profile.private_key)))
User.enc = property(lambda u: UserRibbitEncryption.objects.get_or_create(user=u)[0])
Ribbit.get_rebbit = property(lambda u: Ribbit.objects.get_or_create(id=u.id)[0])
Ribbit.original_user = property(lambda u: User.objects.get_or_create(id=u.retweeted)[0])
