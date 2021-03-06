# Generated by Django 2.1.7 on 2019-02-28 19:58

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('user', '0002_auto_20181231_1623'),
    ]

    operations = [
        migrations.CreateModel(
            name='UserLogin',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('login_date', models.DateTimeField(auto_now_add=True, null=True)),
                ('ip', models.CharField(blank=True, default='', max_length=50, null=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='login_time', to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
