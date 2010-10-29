/*
 * This file is part of .Net ETEE for eHealth.
 * 
 * .Net ETEE for eHealth is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * .Net ETEE for eHealth  is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.

 * You should have received a copy of the GNU Lesser General Public License
 * along with Foobar.  If not, see <http://www.gnu.org/licenses/>.
 */

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.ComponentModel;

namespace Siemens.EHealth.Etee.Crypto.Library
{
    public abstract class Recipient : INotifyPropertyChanged, IEditableObject
    {
        private class PropertyValues
        {
            public Object curVal;
            public Object newVal;
        }

        private bool edit = false;

        private String recipientType;

        private Dictionary<String, PropertyValues> propertyValues = new Dictionary<string, PropertyValues>();

        protected Recipient(String recipientType)
        {
            this.recipientType = recipientType;
        }

        public String RecipientType
        {
            get
            {
                return recipientType;
            }
        }

        protected Object this[String property]
        {
            get
            {
                if (!propertyValues.ContainsKey(property)) return null;

                PropertyValues val = propertyValues[property];
                if (edit)
                {
                    return val.newVal;
                }
                else
                {
                    return val.curVal;
                }
            }
            set
            {
                PropertyValues val;
                if (!propertyValues.ContainsKey(property))
                {
                    val = new PropertyValues();
                    propertyValues[property] = val;
                }
                else
                {
                    val = propertyValues[property];
                }
                if (edit)
                {
                    val.newVal = value;
                }
                else
                {
                    val.curVal = value;
                }
                OnPropertyChanged(new PropertyChangedEventArgs(property));
            }
        }
       
        protected virtual void OnPropertyChanged(PropertyChangedEventArgs e)
        {
            if (PropertyChanged != null)
            {
                PropertyChanged.Invoke(this, e);
            }
        }

        #region INotifyPropertyChanged Members

        public event PropertyChangedEventHandler PropertyChanged;

        #endregion

        #region IEditableObject Members

        void IEditableObject.BeginEdit()
        {
            if (!edit)
            {
                foreach (PropertyValues value in propertyValues.Values)
                {
                    value.newVal = value.curVal;
                }
            }
        }

        void IEditableObject.CancelEdit()
        {
            edit = false;
            foreach (String prop in propertyValues.Keys)
            {
                PropertyValues propVal = propertyValues[prop];
                if (propVal.curVal == null)
                {
                    propertyValues.Remove(prop);
                }
                else
                {
                    propVal.newVal = null;
                }
            }
        }

        void IEditableObject.EndEdit()
        {
            if (edit)
            {
                edit = false;
                foreach (String prop in propertyValues.Keys)
                {
                    PropertyValues propVal = propertyValues[prop];
                    if (propVal.newVal == null)
                    {
                        propertyValues.Remove(prop);
                    }
                    else
                    {
                        propVal.curVal = propVal.newVal;
                        propVal.newVal = null;
                    }
                }
            }
        }

        #endregion
    }
}
