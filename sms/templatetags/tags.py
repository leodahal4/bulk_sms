from django import template
register = template.Library()


# @register.filter(name='int_eng')
# def convertIntToNepali(nep_int):
# 	eng_nums = ('0', '1', '2', '3', '4', '5', '6', '7', '8', '9')
# 	number = str(int(nep_int))
# 	return ''.join(eng_nums[int(digit)] for digit in number)


@register.simple_tag
def changeclass(path,some_id):
	x = path.split('/')
	y = x[2]
	if int(y) == some_id:
		return str('active show')
	else:
		return str('')


@register.simple_tag
def changeclassen(path,some_id):
	x = path.split('/')
	y = x[3]
	if int(y) == int(some_id):
		return str('active show')
	else:
		return str('')


@register.filter(name='src')
def changeurl(url):
	x = url
	y = x.replace('embed/','watch?v=')
	return y


# to change url from nepali to english
@register.filter(name='change_lang')
def change_lang(path):
	initial_url = path

	if '/en/' in initial_url:
		return initial_url[3:]
	else:
		return '/en{}'.format(initial_url)


# tags for administraion of moics
@register.filter(name='change_class_valid')
def addclass(field, given_class):
	existing_classes = field.field.widget.attrs.get('class', None)
	if field.errors:
		if existing_classes:
			if existing_classes.find(given_class) == -1:
				# if the given class doesn't exist in the existing classes
				classes = existing_classes + ' ' + given_class
			else:
				classes = existing_classes
		else:
			classes = given_class
		return field.as_widget(attrs={"class": classes})
	else:
		return field.as_widget(attrs={"class": existing_classes})


# tags for returning count of sms recipients
@register.filter(name='recipients')
def recipients_count(recipients):
	if recipients:
		recipients = recipients.split(',')
		return len(recipients)
	return None


@register.filter(name='index')
def index(d, value):
    return d[value]