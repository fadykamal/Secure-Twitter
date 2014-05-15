# -*- coding: utf-8 -*-
from south.utils import datetime_utils as datetime
from south.db import db
from south.v2 import SchemaMigration
from django.db import models


class Migration(SchemaMigration):

    def forwards(self, orm):
        # Deleting field 'FollowRequest.requested'
        db.delete_column(u'ribbit_app_followrequest', 'requested')


    def backwards(self, orm):
        # Adding field 'FollowRequest.requested'
        db.add_column(u'ribbit_app_followrequest', 'requested',
                      self.gf('django.db.models.fields.BooleanField')(default=False),
                      keep_default=False)


    models = {
        u'auth.group': {
            'Meta': {'object_name': 'Group'},
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '80'}),
            'permissions': ('django.db.models.fields.related.ManyToManyField', [], {'to': u"orm['auth.Permission']", 'symmetrical': 'False', 'blank': 'True'})
        },
        u'auth.permission': {
            'Meta': {'ordering': "(u'content_type__app_label', u'content_type__model', u'codename')", 'unique_together': "((u'content_type', u'codename'),)", 'object_name': 'Permission'},
            'codename': ('django.db.models.fields.CharField', [], {'max_length': '100'}),
            'content_type': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['contenttypes.ContentType']"}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '50'})
        },
        u'auth.user': {
            'Meta': {'object_name': 'User'},
            'date_joined': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime.now'}),
            'email': ('django.db.models.fields.EmailField', [], {'max_length': '75', 'blank': 'True'}),
            'first_name': ('django.db.models.fields.CharField', [], {'max_length': '30', 'blank': 'True'}),
            'groups': ('django.db.models.fields.related.ManyToManyField', [], {'symmetrical': 'False', 'related_name': "u'user_set'", 'blank': 'True', 'to': u"orm['auth.Group']"}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'is_active': ('django.db.models.fields.BooleanField', [], {'default': 'True'}),
            'is_staff': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'is_superuser': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'last_login': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime.now'}),
            'last_name': ('django.db.models.fields.CharField', [], {'max_length': '30', 'blank': 'True'}),
            'password': ('django.db.models.fields.CharField', [], {'max_length': '128'}),
            'user_permissions': ('django.db.models.fields.related.ManyToManyField', [], {'symmetrical': 'False', 'related_name': "u'user_set'", 'blank': 'True', 'to': u"orm['auth.Permission']"}),
            'username': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '30'})
        },
        u'contenttypes.contenttype': {
            'Meta': {'ordering': "('name',)", 'unique_together': "(('app_label', 'model'),)", 'object_name': 'ContentType', 'db_table': "'django_content_type'"},
            'app_label': ('django.db.models.fields.CharField', [], {'max_length': '100'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'model': ('django.db.models.fields.CharField', [], {'max_length': '100'}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '100'})
        },
        u'ribbit_app.follow': {
            'Meta': {'object_name': 'Follow'},
            'followed': ('django.db.models.fields.related.ForeignKey', [], {'related_name': "'followed'", 'to': u"orm['auth.User']"}),
            'follower': ('django.db.models.fields.related.ForeignKey', [], {'related_name': "'follower'", 'to': u"orm['auth.User']"}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'})
        },
        u'ribbit_app.followrequest': {
            'Meta': {'object_name': 'FollowRequest'},
            'answer': ('django.db.models.fields.CharField', [], {'max_length': '1024', 'null': 'True', 'blank': 'True'}),
            'answered': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'followed': ('django.db.models.fields.related.ForeignKey', [], {'related_name': "'rfollowed'", 'to': u"orm['auth.User']"}),
            'follower': ('django.db.models.fields.related.ForeignKey', [], {'related_name': "'rfollower'", 'to': u"orm['auth.User']"}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'question': ('django.db.models.fields.CharField', [], {'max_length': '1024', 'null': 'True', 'blank': 'True'})
        },
        u'ribbit_app.messages': {
            'Meta': {'object_name': 'Messages'},
            'content': ('django.db.models.fields.CharField', [], {'max_length': '2048'}),
            'creation_date': ('django.db.models.fields.DateTimeField', [], {'auto_now': 'True', 'blank': 'True'}),
            'd_sign': ('django.db.models.fields.CharField', [], {'default': "''", 'max_length': '128'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'receiver': ('django.db.models.fields.related.ForeignKey', [], {'related_name': "'receiver'", 'to': u"orm['auth.User']"}),
            'salt': ('django.db.models.fields.CharField', [], {'default': "''", 'max_length': '64'}),
            'sender': ('django.db.models.fields.related.ForeignKey', [], {'related_name': "'sender'", 'to': u"orm['auth.User']"})
        },
        u'ribbit_app.ribbit': {
            'Meta': {'object_name': 'Ribbit'},
            'content': ('django.db.models.fields.CharField', [], {'max_length': '140'}),
            'creation_date': ('django.db.models.fields.DateTimeField', [], {'auto_now': 'True', 'blank': 'True'}),
            'd_sign': ('django.db.models.fields.CharField', [], {'default': "''", 'max_length': '128'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'retweeted': ('django.db.models.fields.IntegerField', [], {'default': '0'}),
            'user': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['auth.User']"})
        },
        u'ribbit_app.ribbitforfollowers': {
            'Meta': {'object_name': 'RibbitForFollowers'},
            'd_sign': ('django.db.models.fields.CharField', [], {'default': "''", 'max_length': '128'}),
            'encrypted_content': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['auth.User']"}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'public_key': ('django.db.models.fields.CharField', [], {'max_length': '140'})
        },
        u'ribbit_app.userprofile': {
            'Meta': {'object_name': 'UserProfile'},
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'private_key': ('django.db.models.fields.CharField', [], {'max_length': '1024'}),
            'user': ('django.db.models.fields.related.OneToOneField', [], {'to': u"orm['auth.User']", 'unique': 'True'})
        },
        u'ribbit_app.userribbitencryption': {
            'Meta': {'object_name': 'UserRibbitEncryption'},
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'public_key': ('django.db.models.fields.CharField', [], {'max_length': '1024'}),
            'user': ('django.db.models.fields.related.OneToOneField', [], {'to': u"orm['auth.User']", 'unique': 'True'})
        }
    }

    complete_apps = ['ribbit_app']