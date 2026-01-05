/* ===== THIS SCRIPT FOR ADMIN AND INDEX  ===== */

paper.install(window);

window.onload = function () {

    const canvas = document.getElementById('canvas');
    paper.setup(canvas);

    const moneySign = document.getElementById('money');

    let money = new Point(view.size.width / 2, view.size.height / 2);

    document.addEventListener('mousemove', (e) => {
        money.x = e.clientX;
        money.y = e.clientY;

        moneySign.style.left = e.clientX + 'px';
        moneySign.style.top  = e.clientY + 'px';
    });

    const hands = [];

    for (let i = 0; i < 40; i++) {
        let hand = new Path.Circle({
            center: Point.random().multiply(view.size),
            radius: random(8, 15),
            fillColor: '#ffcc99'
        });

        hand.velocity = new Point(0, 0);
        hand.mass = random(8, 12);
        hand.limit = random(3, 6);

        hands.push(hand);
    }

    view.onFrame = function () {
        hands.forEach(hand => {

            let force = money.subtract(hand.position);
            let distance = Math.max(20, Math.min(force.length, 150));

            force = force.normalize();
            force = force.multiply(200 / (distance * distance));

            hand.velocity = hand.velocity.add(force);

            if (hand.velocity.length > hand.limit) {
                hand.velocity.length = hand.limit;
            }

            hand.position = hand.position.add(hand.velocity);
        });
    };

    function random(a, b) {
        return Math.random() * (b - a) + a;
    }
};




