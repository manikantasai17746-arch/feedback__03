"""Teacher dashboard: subject-scoped, anonymous, published-only results."""
from flask import Blueprint, abort, render_template, request

from . import services
from .security import current_user, role_required

bp = Blueprint('teacher', __name__, url_prefix='/teacher')


@bp.route('/')
@role_required('teacher')
def dashboard():
    user = current_user()
    subjects = services.teacher_subjects(user['id'])
    subject_code = request.args.get('subject_code') or None
    # Only one subject taught? show it directly, no forced selection.
    if subject_code is None and len(subjects) == 1:
        subject_code = subjects[0]['subject_code']
    if subject_code and subject_code not in {s['subject_code'] for s in subjects}:
        abort(403)

    forms = services.teacher_published_forms(user['id'], subject_code=subject_code)
    rows = []
    for f in forms:
        # Count only this teacher's own sessions within a (possibly shared) form.
        session_ids = services.teacher_form_session_ids(user['id'], f['id'])
        rows.append({'form': f,
                     'responses': services.response_count(f['id'], session_ids=session_ids)})
    total_published = len(services.teacher_published_forms(user['id']))
    return render_template('teacher_dashboard.html', user=user, subjects=subjects,
                           subject_code=subject_code, rows=rows,
                           total_published=total_published)


@bp.route('/results/<int:form_id>')
@role_required('teacher')
def results(form_id):
    user = current_user()
    # Authorisation: the form must be one of THIS teacher's published forms.
    allowed = {f['id']: f for f in services.teacher_published_forms(user['id'])}
    form = allowed.get(form_id)
    if not form:
        abort(403)

    # Restrict statistics to this teacher's own sessions inside the form, so a
    # shared subject-scoped form never exposes another teacher's responses.
    session_ids = services.teacher_form_session_ids(user['id'], form_id)
    stats = services.question_stats(form_id, session_ids=session_ids)
    page = request.args.get('page', 1, type=int)
    suggestions = services.suggestions_paged(form_id, page=page, per_page=10,
                                             session_ids=session_ids)
    responses = services.response_count(form_id, session_ids=session_ids)
    return render_template('teacher_results.html', user=user, form=form, stats=stats,
                           suggestions=suggestions, responses=responses)
