# Generated by Django 2.2.4 on 2019-08-26 17:05

from django.db import migrations, models
import project.validators


class Migration(migrations.Migration):

    dependencies = [
        ('project', '0030_auto_20190807_1220'),
    ]

    operations = [
        migrations.AlterField(
            model_name='activeproject',
            name='slug',
            field=models.SlugField(max_length=30),
        ),
        migrations.AlterField(
            model_name='archivedproject',
            name='slug',
            field=models.SlugField(max_length=30),
        ),
        migrations.AlterField(
            model_name='publishedproject',
            name='slug',
            field=models.SlugField(max_length=30, validators=[project.validators.validate_slug]),
        ),
    ]
