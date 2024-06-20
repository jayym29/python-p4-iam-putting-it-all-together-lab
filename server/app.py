#!/usr/bin/env python3

from flask import request, session, make_response
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

class Signup(Resource):
    
    def post(self):
        try: 
            data = request.get_json()
            user = User(username=data['username'], image_url=data['image_url'], bio=data['bio'],)
            user.password_hash = data['password']
            db.session.add(user)
            db.session.commit()
            return make_response(user.to_dict(), 201)
        except IntegrityError as i_error:
            return make_response({"error": str(i_error)}, 400)
        except KeyError as k_error:
            return make_response({"error": "Missing required field: " + str(k_error)}, 422)


class CheckSession(Resource):
    
    def get(self):

        user_id = session["user_id"]
        if user_id:
            user = User.query.filter_by(id = user_id).first()
            return make_response(user.to_dict(), 200)
        else:
            return make_response({"error": "No session found"}, 401)

class Login(Resource):
    
    def post(self):
        username = request.get_json()['username']
        password = request.get_json()['password']
        user = User.query.filter(User.username == username).first()
        if user:
            try: 
                if user.authenticate(password):
                    session['user_id'] = user.id
                    return make_response(user.to_dict(), 200)
            except KeyError as k_error:
                return make_response({"error": "Missing required field: " + str(k_error)}, 422)
        
        return make_response({'error': '401 Unauthorized'}, 401)

class Logout(Resource):
    def delete(self):
        if 'user_id' not in session or session['user_id'] is None:
            return make_response({"error": "No user logged in"}, 401)

        # User is logged in, proceed with logout
        session['user_id'] = None
        
        return {}, 204

class RecipeIndex(Resource):
    def get(self):
        if 'user_id' not in session or session['user_id'] is None:
            return make_response({"error": "No user logged in"}, 401)
        user_id = session['user_id']
        recipes = Recipe.query.filter_by(user_id=user_id).all()
        recipes_list = [recipe.to_dict() for recipe in recipes]
        return make_response(recipes_list, 200)
    
    def post(self):
        if 'user_id' not in session or session['user_id'] is None:
            return make_response({"error": "No user logged in"}, 401)
        data = request.get_json()
        try: 
            recipe = Recipe(title=data['title'], instructions=data['instructions'], minutes_to_complete=data['minutes_to_complete'], user_id=session['user_id'])
            db.session.add(recipe)
            db.session.commit()
            return make_response(recipe.to_dict(), 201)
        except ValueError as v_error:
            return make_response({"error": str(v_error)}, 422)
    


api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)