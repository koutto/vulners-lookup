===============
Vulners-lookup
===============

**Small script to perform vulnerabilities/exploits lookup on Vulners Database (https://vulners.com/)**.

Vulners aggregates lots of various sources (including exploit-db, 0day.today, Nessus db, OpenVAS db...), 
see https://vulners.com/stats for a complete list.

This script is using Vulners Python API available at https://github.com/vulnersCom/api

Thanks to Vulners team for providing this great service !


============
Installation
============

Install Python3 dependencies:

.. code-block:: console

	sudo pip3 install -r requirements.txt


=====
Usage
=====

**Search for vulnerabilities & exploit:**

.. code-block:: console

	python3 vulners-lookup.py --apikey <your-API-key> 'product name/version to search'

=======
Example
=======

.. image:: ./pictures/vulners-lookup-screenshot.png