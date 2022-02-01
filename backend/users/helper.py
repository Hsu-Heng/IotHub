# -*- encoding: utf-8 -*-


def get_or_none_raw_sql(classmodel, raw, parameters):
    try:
        return classmodel.objects.raw(raw, parameters)
    except classmodel.DoesNotExist:
        return None
    except ValueError:
        return None
    except Exception as e:
        return None
