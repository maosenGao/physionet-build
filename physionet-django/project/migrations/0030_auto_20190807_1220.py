# Generated by Django 2.2.3 on 2019-08-07 16:20

from django.db import migrations, models
from project.models import PublishedProject


featured = {}
def save_featured(apps, schema_editor):
    projects = PublishedProject.objects.filter(featured=True)

    i = 1
    for p in projects:
        featured[p.pk] = i
        i += 1

def migrate_featured(apps, schema_editor):
    for p, i in featured.items():
        PublishedProject.objects.filter(pk=p).update(featured=i)

        
class Migration(migrations.Migration):

    dependencies = [
        ('project', '0029_publishedproject_display_publications'),
    ]

    operations = [
        migrations.RunPython(save_featured),
        migrations.RemoveField(
            model_name='publishedproject',
            name='featured',
        ),
        migrations.AddField(
            model_name='publishedproject',
            name='featured',
            field=models.PositiveSmallIntegerField(null=True),
        ),
        migrations.RunPython(migrate_featured),
        migrations.AlterUniqueTogether(
            name='publishedproject',
            unique_together={('featured',), ('core_project', 'version')},
        ),
    ]
