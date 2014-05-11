django-ribbit
=============

Ribbit - A Twitter Clone made using Django

A live demo of the app can be found at http://vast-earth-7154.herokuapp.com/

***

To set the application locally, first clone the repo

```  
git clone https://github.com/gnarula/django-ribbit.git
```

Make a virtual environment

```
virtualenv --no-site-packages ribbit_env
```

With the the virtual environment activated, install the dependencies

```
pip install Django South
```

Next, `cd` into the repository and run the `syncdb` command to create the tables and superuser account

```
python manage.py syncdb
```

Then, apply the migrations

```
python manage.py migrate ribbit_app
```

Finally, start the development server to preview the application

```
python manage.py runserver
```

Some notes regarding issues running the project

1- to ensure database migrations as a workaround use the following

```
python manage.py syncdb --all
```

```
python manage.py migrate ribbit_app --fake
```
but try to use the appropriate way when changing a model by executing the following process:
Chnage in the models
```
python manage.py schemamigration ribbit_app --auto
```
```
python manage.py migrate ribbit_app
```
and you're done

2- if you'd like to edit in the css, edit in the directory `ribbit_app/static/style.less` and it's compiled automatically