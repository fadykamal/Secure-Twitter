from django.db import models
from django.contrib.auth.models import User
import hashlib
import bcrypt

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
	salt = models.CharField(max_length=64, default="")
	d_sign = models.CharField(max_length=128, default="")

	def __unicode__(self):
		return u'%s %s %s' % (self.sender,":",self.content)

	def digital_sign(self):
		salt = bcrypt.gensalt()
		sign = bcrypt.hashpw(self.content.encode('utf-8'),
                salt)

		self.salt = salt
		self.d_sign = sign
		self.save()
		return sign

User.profile = property(lambda u: UserProfile.objects.get_or_create(user=u)[0])
User.enc = property(lambda u: UserRibbitEncryption.objects.get_or_create(user=u)[0])

