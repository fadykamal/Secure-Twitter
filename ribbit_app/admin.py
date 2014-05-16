from django.contrib import admin
from ribbit_app.models import *

admin.site.register(Ribbit)
admin.site.register(UserProfile)
admin.site.register(UserRibbitEncryption)
admin.site.register(RibbitForFollowers)
admin.site.register(Messages)
admin.site.register(Follow)
admin.site.register(FollowRequest)
