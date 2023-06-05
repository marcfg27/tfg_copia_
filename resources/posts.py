from flask_restful import Resource, reqparse
from markupsafe import escape
from unidecode import unidecode
from LogManager import validation
from flask import request
from lock import lock
from models.PostsModel import PostsModel
from models.accounts import  g


class Posts(Resource):
   # @require_access('g_posts')
    def get(self):
        parser = reqparse.RequestParser()
        parser.add_argument("limit", type=int, required=False, nullable=False, location="args")
        parser.add_argument("offset", type=int, required=False, nullable=False, location="args")
        data = parser.parse_args()
        posts = PostsModel.get_comments(data["limit"], data["offset"])
        if posts:
            return {"posts": [post.json() for post in posts]}, 200
        return {"posts": []}, 200

   # @require_access('c_posts')
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument("text", type=str, required=True, nullable=False)
        data = parser.parse_args()
        acc = g.user

        with lock.lock:
            if(acc):
                txt = escape(data["text"])
                #txt = data['text']
                txt = unidecode(txt)
                if(len(txt)>280):
                    validation.input_validation_fail_text_caller(acc.username,request)
                    return {"message": "An error occurred creating the post"}, 500

                new_post = PostsModel(txt)
                new_post.account = acc
                try:
                    new_post.save_to_db()
                except Exception as e:
                    return {"message": "An error occurred creating the post"}, 500
                return {"post": new_post.json()}, 201
            else:
                return {"message": "An error occurred creating the post"}, 500

   # @require_access('d_posts')
    def delete(self):
        parser = reqparse.RequestParser()
        parser.add_argument("id", type=str, required=True, nullable=False)
        parser.add_argument("limit", type=int, required=False, nullable=False, location="args")
        parser.add_argument("offset", type=int, required=False, nullable=False, location="args")
        data = parser.parse_args()
        post = PostsModel.get_by_id(data["id"])
        if post is None:
            return {"message": "No post was found"}, 404
        if post.account.username != g.user.username:
            return {"message": "Unauthorized!"}, 403
        try:
            post.delete_from_db()
            posts = PostsModel.get_comments(data["limit"], data["offset"])
            if posts:
                return {"posts": [post.json() for post in posts]}, 200
        except Exception as e:
            return {"message": "An error occurred deleting the post"}, 500
        return {"message": "Post deleted successfully!"}, 200

