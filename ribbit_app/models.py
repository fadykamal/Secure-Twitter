from django.db import models
from django.contrib.auth.models import User
import hashlib


class Ribbit(models.Model):
	content = models.CharField(max_length=140)
	user = models.ForeignKey(User)
	creation_date = models.DateTimeField(auto_now=True, blank=True)

class UserRibbitEncryption(models.Model):
	user = models.OneToOneField(User)
	public_key = models.CharField(max_length = 100)

class UserProfile(models.Model):
	user = models.OneToOneField(User)
	follows = models.ManyToManyField('self', related_name='followed_by', symmetrical=False)
	private_key = models.CharField(max_length = 100)
	
	def __unicode__(self):
		return u'%s' % (self.user)
	def gravatar_url(self):
		return "http://www.gravatar.com/avatar/%s?s=50" % hashlib.md5(self.user.email).hexdigest()

class Messages(models.Model):
	sender = models.ForeignKey(User, related_name='sender')
	receiver = models.ForeignKey(User, related_name='receiver')
	content = models.CharField(max_length=2048)

	def __unicode__(self):
		return u'%s %s %s' % (self.sender,":",self.content)

User.profile = property(lambda u: UserProfile.objects.get_or_create(user=u)[0])
