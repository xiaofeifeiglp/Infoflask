from flask import render_template, g, redirect, url_for, abort, request, jsonify, current_app

from info import db
from info.constants import USER_COLLECTION_MAX_NEWS, QINIU_DOMIN_PREFIX
from info.models import tb_user_collection, Category, News
from info.modules.user import user_blu
from info.utils.common import user_login_data, file_upload

# 个人中心
from info.utils.response_code import RET, error_map


@user_blu.route('/user_info')
@user_login_data
def user_info():
    user = g.user
    if not user:  # 用户未登录, 直接跳转到首页
        return redirect(url_for("home.index"))

    return render_template("news/user.html", user=user.to_dict())


# 基本资料
@user_blu.route('/base_info', methods=['GET', "POST"])
@user_login_data
def base_info():
    user = g.user
    if not user:
        return abort(403)  # 拒绝访问

    if request.method == 'GET':
        return render_template("news/user_base_info.html", user=user.to_dict())
    # POST处理
    signature = request.json.get("signature")
    nick_name = request.json.get("nick_name")
    gender = request.json.get("gender")

    # 校验参数
    if not all([signature, nick_name, gender]):
        return jsonify(errno=RET.PARAMERR, errmsg=error_map[RET.PARAMERR])
    
    if gender not in ["MAN", "WOMAN"]:
        return jsonify(errno=RET.PARAMERR, errmsg=error_map[RET.PARAMERR])

    # 修改用户模型
    user.signature = signature
    user.nick_name = nick_name
    user.gender = gender

    # json返回  需要传入用户信息, 以便前端进行渲染
    return jsonify(errno=RET.OK, errmsg=error_map[RET.OK], data=user.to_dict())


# 显示/修改头像
@user_blu.route('/pic_info', methods=['GET', 'POST'])
@user_login_data
def pic_info():
    user = g.user
    if not user:
        return abort(403)  # 拒绝访问

    if request.method == 'GET':
        return render_template("news/user_pic_info.html", user=user.to_dict())
    # POST处理
    file = request.files.get("avatar")
    try:
        img_bytes = file.read()  # 读取上传文件的二进制格式数据  bytes
        # 一般上传的文件会放到一个单独的文件服务器中进行管理  只需要获取文件名
        try:
            file_name = file_upload(img_bytes)
        except BaseException as e:
            current_app.logger.error(e)
            return jsonify(errno=RET.THIRDERR, errmsg=error_map[RET.THIRDERR])

        # 修改用户模型
        user.avatar_url = file_name

    except BaseException as e:
        current_app.logger.error(e)
        return jsonify(errno=RET.PARAMERR, errmsg=error_map[RET.PARAMERR])

    # 需要回传用户信息, 以便前端来更新头像
    return jsonify(errno=RET.OK, errmsg=error_map[RET.OK], data=user.to_dict())
    

# 我的收藏列表
@user_blu.route('/collection')
@user_login_data
def collection():
    user = g.user
    if not user:
        return abort(403)  # 拒绝访问

    # 获取参数
    p = request.args.get("p", 1)
    try:
        p = int(p)
    except BaseException as e:
        current_app.logger.error(e)
        return abort(403)

    # 查询当前用户收藏的所有新闻  按照收藏时间倒序
    try:
        pn = user.collection_news.order_by(tb_user_collection.c.create_time.desc()).paginate(p, USER_COLLECTION_MAX_NEWS)
    except BaseException as e:
        current_app.logger.error(e)

    data = {
        "news_list": [news.to_dict() for news in pn.items],
        "cur_page": p,
        "total_page": pn.pages
    }

    # 将新闻数据传入模板渲染
    return render_template("news/user_collection.html", data=data)


# 显示/修改密码
@user_blu.route('/pass_info', methods=['GET', 'POST'])
@user_login_data
def pass_info():
    user = g.user
    if not user:
        return abort(403)  # 拒绝访问

    if request.method == 'GET':  # 显示页面
        return current_app.send_static_file("news/html/user_pass_info.html")

    # POST处理
    # 获取参数
    old_password = request.json.get("old_password")
    new_password = request.json.get("new_password")
    # 校验参数
    if not all([old_password, new_password]):
        return jsonify(errno=RET.PARAMERR, errmsg=error_map[RET.PARAMERR])
    # 校验密码
    if not user.check_password(old_password):  # 密码错误
        return jsonify(errno=RET.PARAMERR, errmsg=error_map[RET.PARAMERR])
    # 修改密码(修改模型)
    user.password = new_password
    # json返回
    return jsonify(errno=RET.OK, errmsg=error_map[RET.OK])


# 新闻发布
@user_blu.route('/news_release', methods=['GET', 'POST'])
@user_login_data
def news_release():
    user = g.user
    if not user:
        return abort(403)  # 拒绝访问

    if request.method == 'GET':  # 显示页面
        # 查询所有的分类, 传入模板
        try:
            categories = Category.query.all()
        except BaseException as e:
            current_app.logger.error(e)
            return abort(403)  # 拒绝访问

        if len(categories):  # 删除最新
            categories.pop(0)

        return render_template("news/user_news_release.html", categories=categories)

    # POST处理
    title = request.form.get("title")
    category_id = request.form.get("category_id")
    digest = request.form.get("digest")
    content = request.form.get("content")
    if not all([title, category_id, digest, content]):
        return jsonify(errno=RET.PARAMERR, errmsg=error_map[RET.PARAMERR])

    try:
        category_id = int(category_id)
        category = Category.query.get(category_id)
    except BaseException as e:
        current_app.logger.error(e)
        return jsonify(errno=RET.PARAMERR, errmsg=error_map[RET.PARAMERR])

    if not category:
        return jsonify(errno=RET.PARAMERR, errmsg=error_map[RET.PARAMERR])

    # 生成新闻数据
    news = News()
    news.title = title
    news.digest = digest
    news.content = content
    news.category_id = category_id
    news.source = "个人发布"  # 新闻来源
    news.user_id = user.id  # 新闻作者
    news.status = 1  # 状态 1表示待审核
    # 设置图片
    try:
        img_bytes = request.files.get("index_image").read()
        # 上传图片, 获取图片的访问链接
        try:
            file_name = file_upload(img_bytes)
            news.index_image_url = QINIU_DOMIN_PREFIX + file_name

        except BaseException as e:
            current_app.logger.error(e)
            return jsonify(errno=RET.THIRDERR, errmsg=error_map[RET.THIRDERR])

    except BaseException as e:
        current_app.logger.error(e)
        return jsonify(errno=RET.PARAMERR, errmsg=error_map[RET.PARAMERR])


    db.session.add(news)
    
    return jsonify(errno=RET.OK, errmsg=error_map[RET.OK])


# 我的发布列表
@user_blu.route('/news_list')
@user_login_data
def news_list():
    user = g.user
    if not user:
        return abort(403)  # 拒绝访问

    # 获取参数
    p = request.args.get("p", 1)
    try:
        p = int(p)
    except BaseException as e:
        current_app.logger.error(e)
        return abort(403)

    # 查询当前用户发布的所有新闻  按照发布时间倒序
    try:
        pn = user.news_list.order_by(News.create_time.desc()).paginate(p, USER_COLLECTION_MAX_NEWS)
    except BaseException as e:
        current_app.logger.error(e)

    data = {
        "news_list": [news.to_review_dict() for news in pn.items],
        "cur_page": p,
        "total_page": pn.pages
    }

    # 将新闻数据传入模板渲染
    return render_template("news/user_news_list.html", data=data)


# 我的关注列表
@user_blu.route('/user_follow')
@user_login_data
def user_follow():
    user = g.user
    if not user:
        return abort(403)  # 拒绝访问

    # 获取参数
    p = request.args.get("p", 1)
    try:
        p = int(p)
    except BaseException as e:
        current_app.logger.error(e)
        return abort(403)

    # 查询当前用户关注的所有作者
    try:
        pn = user.followed.paginate(p, USER_COLLECTION_MAX_NEWS)
    except BaseException as e:
        current_app.logger.error(e)

    data = {
        "author_list": [author.to_dict() for author in pn.items],
        "cur_page": p,
        "total_page": pn.pages
    }

    # 将新闻数据传入模板渲染
    return render_template("news/user_follow.html", data=data)
