# Generated by Django 2.1.7 on 2019-07-23 17:52

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('project', '0024_auto_20190708_1810'),
    ]

    operations = [
        migrations.AlterField(
            model_name='editlog',
            name='editor_comments',
            field=models.CharField(max_length=10000),
        ),
    ]